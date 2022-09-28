/**
 * @file lcz_pki_auth_smp_central.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_pki_auth_smp_central, CONFIG_LCZ_PKI_AUTH_LOG_LEVEL);

#include <zephyr.h>
#include <init.h>
#include <mgmt/mgmt.h>
#include <mgmt/mcumgr/smp_bt.h>
#include <zcbor_common.h>
#include <zcbor_decode.h>
#include <zcbor_encode.h>
#include <zcbor_bulk/zcbor_bulk_priv.h>
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"
#include "psa/error.h"
#include <bluetooth/conn.h>
#include <bluetooth/gatt.h>
#include <bluetooth/gatt_dm.h>
#include <bluetooth/services/dfu_smp.h>
#include "lcz_lwm2m_gateway_obj.h"

#include "lcz_pki_auth.h"
#include "lcz_pki_auth_smp.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define LCZ_PKI_AUTH_MAX_PACKET 2048

/* Amount of time that authentication transaction must complete within before timeout occurs */
#define AUTH_TIMEOUT K_SECONDS(10)

typedef enum {
	LCZ_PKI_AUTH_CENTRAL_STATE_START,
	LCZ_PKI_AUTH_CENTRAL_STATE_RESUME,
	LCZ_PKI_AUTH_CENTRAL_STATE_VERIFY,
	LCZ_PKI_AUTH_CENTRAL_STATE_STATUS,
} LCZ_PKI_AUTH_CENTRAL_STATE_T;

/* Temporary data in use during a BLE connection */
typedef struct {
	LCZ_PKI_AUTH_CENTRAL_STATE_T state;

	struct bt_dfu_smp *smp_client;

	uint8_t auth_handshake_hash[LCZ_PKI_AUTH_SMP_HANDSHAKE_HASH_LEN];

	/* Random seed (gateway + peripheral) */
	uint8_t random_seed[LCZ_PKI_AUTH_RAND_LEN * 2];

	/* Buffer to store packets that we're building */
	struct lwm2m_gw_smp_buffer {
		struct bt_dfu_smp_header header;
		uint8_t payload[LCZ_PKI_AUTH_MAX_PACKET];
	} smp_buf;

	/* Hash operation split over the start/resume and its response */
	psa_hash_operation_t hash_op;

	/* Certificates */
	mbedtls_x509_crt ca_cert;
	mbedtls_x509_crt gateway_cert;
	mbedtls_x509_crt peripheral_cert;

	/* Verification result */
	uint8_t verify_bytes[LCZ_PKI_AUTH_SMP_VERIFY_LEN];
} LCZ_PKI_AUTH_SMP_CENTRAL_TMP_DATA_T;

/* Permanent data used to save authentication session information */
typedef struct {
	LCZ_PKI_AUTH_SMP_CENTRAL_TMP_DATA_T *tmp_data;
	struct k_work sensor_work;

	/* Session expiration time */
	int64_t expires;

	/* Session data */
	uint64_t session_id;
	psa_key_id_t secret_key;
	psa_key_id_t session_enc_key;
	psa_key_id_t session_sig_key;
	uint32_t status;
	bool resumed;

	/* Work handler for authentication timeout */
	struct k_work_delayable timeout_work;
} LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T;

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static void auth_status_callback(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data);
static void reset_tmp_data(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, bool free, bool alloc);
static void reset_auth_data(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, bool free, bool alloc);
static void clean_up_data(int obj_idx, LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data);
static void bt_connected(struct bt_conn *conn, uint8_t conn_err);
static void bt_disconnected(struct bt_conn *conn, uint8_t reason);
static int send_start_message(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data);
static int send_resume_message(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data);
static int send_verify_message(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data);
static int send_status_message(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data);
static void sensor_work_handler(struct k_work *work);
static void handle_start_response(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, zcbor_state_t *zsd);
static void handle_resume_response(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, zcbor_state_t *zsd);
static void handle_verify_response(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, zcbor_state_t *zsd);
static void handle_status_response(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, zcbor_state_t *zsd);
static void smp_client_resp_handler(struct bt_dfu_smp *dfu_smp);
static int session_start(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data);
static int session_resume(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data);
static void device_deleted_cb(int idx, void *data_ptr);
static void auth_timeout_handler(struct k_work *work);
static int lcz_pki_auth_smp_central_init(const struct device *dev);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
/** @brief BT connection callbacks */
static struct bt_conn_cb conn_callbacks = {
	.connected = bt_connected,
	.disconnected = bt_disconnected,
};

static sys_slist_t auth_complete_cb_list = SYS_SLIST_STATIC_INIT(&auth_complete_cb_list);

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
void lcz_pki_auth_smp_central_register_handler(
	struct lcz_pki_auth_smp_central_auth_callback_agent *cb)
{
	sys_slist_append(&auth_complete_cb_list, &cb->node);
}

void lcz_pki_auth_smp_central_unregister_handler(
	struct lcz_pki_auth_smp_central_auth_callback_agent *cb)
{
	(void)sys_slist_find_and_remove(&auth_complete_cb_list, &cb->node);
}

int lcz_pki_auth_smp_central_get_keys(const bt_addr_le_t *addr, psa_key_id_t *enc_key,
				      psa_key_id_t *sig_key)
{
	int ret = -EINVAL;
	int obj_idx;
	LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data;

	/* Look up device in gateway database */
	obj_idx = lcz_lwm2m_gw_obj_lookup_ble(addr);
	if (obj_idx < 0) {
		/* This isn't a device we know about */
		goto done;
	}

	/* Retrieve the security data for the device */
	sec_data = (LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *)lcz_lwm2m_gw_obj_get_security_data(obj_idx);
	if (sec_data == NULL) {
		goto done;
	}

	/* Fail if the authentication has not succeeded */
	if (sec_data->status != LCZ_PKI_AUTH_SMP_STATUS_GOOD) {
		goto done;
	}

	/* Fail if the session has expired */
	if (k_uptime_get() > sec_data->expires) {
		/* Clear all of the session data */
		clean_up_data(obj_idx, sec_data);
		goto done;
	}

	/* Return the keys */
	ret = 0;
	if (enc_key != NULL) {
		*enc_key = sec_data->session_enc_key;
	}
	if (sig_key != NULL) {
		*sig_key = sec_data->session_sig_key;
	}

done:
	return ret;
}

int lcz_pki_auth_smp_central_start_auth(struct bt_dfu_smp *smp_client)
{
	const bt_addr_le_t *addr = bt_conn_get_dst(bt_dfu_smp_conn(smp_client));
	int obj_idx;
	LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data;
	int ret = 0;
	bool resume = false;

	/* Look up device in gateway database */
	obj_idx = lcz_lwm2m_gw_obj_lookup_ble(addr);
	if (obj_idx < 0) {
		/* This isn't a device we know about */
		LOG_ERR("start_auth: Not a known device");
		ret = -EINVAL;
		goto done;
	}

	/* Retrieve the security data for the device */
	sec_data = (LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *)lcz_lwm2m_gw_obj_get_security_data(obj_idx);
	if (sec_data == NULL || sec_data->tmp_data == NULL) {
		LOG_ERR("start_auth: Security data not allocated");
		ret = -ENOMEM;
		goto done;
	}

	/* If the authentication has succeeded recently, resume the session */
	if ((sec_data->status == LCZ_PKI_AUTH_SMP_STATUS_GOOD) &&
	    (k_uptime_get() <= sec_data->expires)) {
		resume = true;
	}

	/* Clear out the old data and prepare to start a new session */
	reset_tmp_data(sec_data, true, true);
	if (resume == false) {
		reset_auth_data(sec_data, true, true);
	}

	/* Save the SMP client pointer for later use */
	sec_data->tmp_data->smp_client = smp_client;

	/* Start a timeout for the process to complete */
	k_work_reschedule(&(sec_data->timeout_work), AUTH_TIMEOUT);

	if (resume) {
		ret = session_resume(sec_data);
	} else {
		ret = session_start(sec_data);
	}

done:
	return ret;
}

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
/**
 * @brief Call any registered callbacks with authentication status
 */
static void auth_status_callback(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data)
{
	sys_snode_t *node;
	struct lcz_pki_auth_smp_central_auth_callback_agent *agent;
	const bt_addr_le_t *addr;
	char addr_str[BT_ADDR_LE_STR_LEN];

	/* Can only send callback for open connections */
	if (sec_data == NULL || sec_data->tmp_data == NULL) {
		return;
	}

	/* Stop the timeout */
	k_work_cancel_delayable(&(sec_data->timeout_work));

	/* Log the event */
	addr = bt_conn_get_dst(bt_dfu_smp_conn(sec_data->tmp_data->smp_client));
	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
	if (sec_data->status == LCZ_PKI_AUTH_SMP_STATUS_GOOD) {
		LOG_INF("SMP authentication %s successful with %s",
			(sec_data->resumed) ? "resume" : "start", addr_str);
	} else {
		LOG_ERR("SMP authentication failed with %s", addr_str);
	}

	/* Call each of the registered callbacks */
	SYS_SLIST_FOR_EACH_NODE (&auth_complete_cb_list, node) {
		agent = CONTAINER_OF(node, struct lcz_pki_auth_smp_central_auth_callback_agent,
				     node);
		if (agent->cb != NULL) {
			agent->cb(addr, (sec_data->status == LCZ_PKI_AUTH_SMP_STATUS_GOOD));
		}
	}
}

static void reset_tmp_data(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, bool free, bool alloc)
{
	int ret;
	struct bt_dfu_smp *smp_client;

	if (sec_data != NULL && sec_data->tmp_data != NULL) {
		smp_client = sec_data->tmp_data->smp_client;

		if (free) {
			/* Free any active data structures */
			psa_hash_abort(&(sec_data->tmp_data->hash_op));
			mbedtls_x509_crt_free(&(sec_data->tmp_data->ca_cert));
			mbedtls_x509_crt_free(&(sec_data->tmp_data->gateway_cert));
			mbedtls_x509_crt_free(&(sec_data->tmp_data->peripheral_cert));
			k_work_cancel(&(sec_data->sensor_work));
			k_work_cancel_delayable(&(sec_data->timeout_work));
		}

		/* Clear the entire data structure */
		memset(sec_data->tmp_data, 0, sizeof(LCZ_PKI_AUTH_SMP_CENTRAL_TMP_DATA_T));

		/* Initialize things that need initializing */
		if (alloc) {
			sec_data->tmp_data->smp_client = smp_client;

			mbedtls_x509_crt_init(&(sec_data->tmp_data->ca_cert));
			mbedtls_x509_crt_init(&(sec_data->tmp_data->gateway_cert));
			mbedtls_x509_crt_init(&(sec_data->tmp_data->peripheral_cert));

			sec_data->tmp_data->hash_op = psa_hash_operation_init();
			ret = psa_hash_setup(&(sec_data->tmp_data->hash_op), PSA_ALG_SHA_256);
			if (ret != PSA_SUCCESS) {
				LOG_ERR("Failed to initialize hash: %d", ret);
			}
		}
	}
}

static void reset_auth_data(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, bool free, bool alloc)
{
	LCZ_PKI_AUTH_SMP_CENTRAL_TMP_DATA_T *tmp_data;

	if (sec_data != NULL) {
		tmp_data = sec_data->tmp_data;

		/* Free any active data structures */
		if (free) {
			psa_destroy_key(sec_data->session_enc_key);
			psa_destroy_key(sec_data->session_sig_key);
			psa_destroy_key(sec_data->secret_key);
			k_work_cancel(&(sec_data->sensor_work));
			k_work_cancel_delayable(&(sec_data->timeout_work));
		}

		/* Clear the entire data structure */
		memset(sec_data, 0, sizeof(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T));

		/* Initialize things that need initializing */
		if (alloc) {
			sec_data->secret_key = PSA_KEY_HANDLE_INIT;
			sec_data->session_enc_key = PSA_KEY_HANDLE_INIT;
			sec_data->session_sig_key = PSA_KEY_HANDLE_INIT;
			sec_data->tmp_data = tmp_data;
			k_work_init(&(sec_data->sensor_work), sensor_work_handler);
			k_work_init_delayable(&(sec_data->timeout_work), auth_timeout_handler);
		}
	}
}

static void clean_up_data(int obj_idx, LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data)
{
	/* Do nothing if there is no data */
	if (sec_data == NULL) {
		return;
	}

	/* Clear all of the temporary data */
	if (sec_data->tmp_data != NULL) {
		reset_tmp_data(sec_data, true, false);
		k_free(sec_data->tmp_data);
	}

	/* Clear all of the session data */
	reset_auth_data(sec_data, true, false);

	/* Remove it from the gateway object database */
	lcz_lwm2m_gw_obj_set_security_data(obj_idx, NULL);

	/* Free the memory */
	k_free(sec_data);
}

static void bt_connected(struct bt_conn *conn, uint8_t conn_err)
{
	LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data;
	int obj_idx;

	/* Look up device in gateway database */
	obj_idx = lcz_lwm2m_gw_obj_lookup_ble(bt_conn_get_dst(conn));
	if (obj_idx < 0) {
		/* This isn't a device we know about. Do nothing. */
		return;
	}

	/* Retrieve the security data for the device */
	sec_data = (LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *)lcz_lwm2m_gw_obj_get_security_data(obj_idx);

	/* If the security data doesn't exist, create it */
	if (sec_data == NULL) {
		sec_data = (LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *)k_malloc(
			sizeof(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T));
		if (sec_data == NULL) {
			LOG_ERR("Could not allocate security data object");
			return;
		} else {
			if (lcz_lwm2m_gw_obj_set_security_data(obj_idx, sec_data) < 0) {
				LOG_ERR("Could not store security data object");
				k_free(sec_data);
				return;
			}

			/* Initialize the security data */
			memset(sec_data, 0, sizeof(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T));
			reset_auth_data(sec_data, false, true);
		}
	}

	/* Create the temporary data if it doesn't exist */
	if (sec_data->tmp_data == NULL) {
		sec_data->tmp_data = (LCZ_PKI_AUTH_SMP_CENTRAL_TMP_DATA_T *)k_malloc(
			sizeof(LCZ_PKI_AUTH_SMP_CENTRAL_TMP_DATA_T));
		if (sec_data->tmp_data == NULL) {
			LOG_ERR("Could not allocate temporary connection data");
			clean_up_data(obj_idx, sec_data);
			return;
		}
	}

	/* Initialize the temporary data */
	reset_tmp_data(sec_data, false, true);
}

static void bt_disconnected(struct bt_conn *conn, uint8_t reason)
{
	LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data;
	int obj_idx;

	/* Look up device in gateway database */
	obj_idx = lcz_lwm2m_gw_obj_lookup_ble(bt_conn_get_dst(conn));
	if (obj_idx < 0) {
		/* This isn't a device we know about. Do nothing. */
		return;
	}

	/* Retrieve the security data for the device */
	sec_data = (LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *)lcz_lwm2m_gw_obj_get_security_data(obj_idx);

	/* Free the temporary data */
	if (sec_data != NULL) {
		if (sec_data->tmp_data != NULL) {
			reset_tmp_data(sec_data, true, false);
			k_free(sec_data->tmp_data);
			sec_data->tmp_data = NULL;
		}
	}
}

static int send_start_message(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data)
{
	zcbor_state_t zs[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];
	struct zcbor_string zstr;
	bool ok;
	uint16_t payload_len;
	int ret;

	/* Build the CBOR message */
	zcbor_new_state(zs, sizeof(zs) / sizeof(zs[0]), sec_data->tmp_data->smp_buf.payload,
			sizeof(sec_data->tmp_data->smp_buf.payload), 1);
	ok = zcbor_map_start_encode(zs, 1);
	if (ok) {
		zstr.len = strlen(LCZ_PKI_AUTH_MGMT_SESSION_ID_STR);
		zstr.value = LCZ_PKI_AUTH_MGMT_SESSION_ID_STR;
		ok = zcbor_tstr_encode(zs, &zstr);
	}
	if (ok) {
		ok = zcbor_uint64_encode(zs, &(sec_data->session_id));
	}
	if (ok) {
		zstr.len = strlen(LCZ_PKI_AUTH_MGMT_RANDOM_STR);
		zstr.value = LCZ_PKI_AUTH_MGMT_RANDOM_STR;
		ok = zcbor_tstr_encode(zs, &zstr);
	}
	if (ok) {
		zstr.len = LCZ_PKI_AUTH_RAND_LEN;
		zstr.value = sec_data->tmp_data->random_seed;
		ok = zcbor_bstr_encode(zs, &zstr);
	}
	if (ok) {
		zstr.len = strlen(LCZ_PKI_AUTH_MGMT_CERTIFICATE_STR);
		zstr.value = LCZ_PKI_AUTH_MGMT_CERTIFICATE_STR;
		ok = zcbor_tstr_encode(zs, &zstr);
	}
	if (ok) {
		zstr.len = sec_data->tmp_data->gateway_cert.raw.len;
		zstr.value = sec_data->tmp_data->gateway_cert.raw.p;
		ok = zcbor_bstr_encode(zs, &zstr);
	}
	if (ok) {
		ok = zcbor_map_end_encode(zs, 1);
	}

	payload_len = (size_t)(zs[0].payload - sec_data->tmp_data->smp_buf.payload);

	/* Fill in SMP message header */
	sec_data->tmp_data->smp_buf.header.op = MGMT_OP_WRITE;
	sec_data->tmp_data->smp_buf.header.flags = 0;
	sec_data->tmp_data->smp_buf.header.len_h8 = (uint8_t)((payload_len >> 8) & 0xFF);
	sec_data->tmp_data->smp_buf.header.len_l8 = (uint8_t)((payload_len >> 0) & 0xFF);
	sec_data->tmp_data->smp_buf.header.group_h8 =
		(uint8_t)((CONFIG_LCZ_PKI_AUTH_SMP_GROUP_ID >> 8) & 0xFF);
	sec_data->tmp_data->smp_buf.header.group_l8 =
		(uint8_t)((CONFIG_LCZ_PKI_AUTH_SMP_GROUP_ID >> 0) & 0xFF);
	sec_data->tmp_data->smp_buf.header.seq = 0;
	sec_data->tmp_data->smp_buf.header.id = LCZ_PKI_AUTH_MGMT_ID_AUTH_START;

	if (ok) {
		ret = bt_dfu_smp_command(sec_data->tmp_data->smp_client, smp_client_resp_handler,
					 sizeof(sec_data->tmp_data->smp_buf.header) + payload_len,
					 &(sec_data->tmp_data->smp_buf));
		if (ret != 0) {
			LOG_ERR("Failed to send auth start message: %d", ret);
			goto fail;
		}
	} else {
		LOG_ERR("Failed to encode auth start message");
		ret = -ENOMEM;
		goto fail;
	}

	/* Add our response to the hash operation */
	ret = psa_hash_update(&(sec_data->tmp_data->hash_op), sec_data->tmp_data->smp_buf.payload,
			      payload_len);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("Failed to add start message to the hash: %d", ret);
		goto fail;
	}

fail:
	return ret;
}

static int send_resume_message(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data)
{
	zcbor_state_t zs[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];
	struct zcbor_string zstr;
	bool ok;
	uint16_t payload_len;
	int ret;

	/* Build the CBOR message */
	zcbor_new_state(zs, sizeof(zs) / sizeof(zs[0]), sec_data->tmp_data->smp_buf.payload,
			sizeof(sec_data->tmp_data->smp_buf.payload), 1);
	ok = zcbor_map_start_encode(zs, 1);
	if (ok) {
		zstr.len = strlen(LCZ_PKI_AUTH_MGMT_SESSION_ID_STR);
		zstr.value = LCZ_PKI_AUTH_MGMT_SESSION_ID_STR;
		ok = zcbor_tstr_encode(zs, &zstr);
	}
	if (ok) {
		ok = zcbor_uint64_encode(zs, &(sec_data->session_id));
	}
	if (ok) {
		zstr.len = strlen(LCZ_PKI_AUTH_MGMT_RANDOM_STR);
		zstr.value = LCZ_PKI_AUTH_MGMT_RANDOM_STR;
		ok = zcbor_tstr_encode(zs, &zstr);
	}
	if (ok) {
		zstr.len = LCZ_PKI_AUTH_RAND_LEN;
		zstr.value = sec_data->tmp_data->random_seed;
		ok = zcbor_bstr_encode(zs, &zstr);
	}
	if (ok) {
		ok = zcbor_map_end_encode(zs, 1);
	}

	payload_len = (size_t)(zs[0].payload - sec_data->tmp_data->smp_buf.payload);

	/* Fill in SMP message header */
	sec_data->tmp_data->smp_buf.header.op = MGMT_OP_WRITE;
	sec_data->tmp_data->smp_buf.header.flags = 0;
	sec_data->tmp_data->smp_buf.header.len_h8 = (uint8_t)((payload_len >> 8) & 0xFF);
	sec_data->tmp_data->smp_buf.header.len_l8 = (uint8_t)((payload_len >> 0) & 0xFF);
	sec_data->tmp_data->smp_buf.header.group_h8 =
		(uint8_t)((CONFIG_LCZ_PKI_AUTH_SMP_GROUP_ID >> 8) & 0xFF);
	sec_data->tmp_data->smp_buf.header.group_l8 =
		(uint8_t)((CONFIG_LCZ_PKI_AUTH_SMP_GROUP_ID >> 0) & 0xFF);
	sec_data->tmp_data->smp_buf.header.seq = 0;
	sec_data->tmp_data->smp_buf.header.id = LCZ_PKI_AUTH_MGMT_ID_AUTH_RESUME;

	if (ok) {
		ret = bt_dfu_smp_command(sec_data->tmp_data->smp_client, smp_client_resp_handler,
					 sizeof(sec_data->tmp_data->smp_buf.header) + payload_len,
					 &(sec_data->tmp_data->smp_buf));
		if (ret != 0) {
			LOG_ERR("Failed to send auth resume message: %d", ret);
			goto fail;
		}
	} else {
		LOG_ERR("Failed to encode auth resume message");
		ret = -ENOMEM;
		goto fail;
	}

	/* Add our response to the hash operation */
	ret = psa_hash_update(&(sec_data->tmp_data->hash_op), sec_data->tmp_data->smp_buf.payload,
			      payload_len);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("Failed to add resume message to the hash: %d", ret);
		goto fail;
	}

fail:
	return ret;
}

static int send_verify_message(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data)
{
	zcbor_state_t zs[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];
	struct zcbor_string zstr;
	bool ok;
	uint16_t payload_len;
	int ret;

	/* Build the CBOR message */
	zcbor_new_state(zs, sizeof(zs) / sizeof(zs[0]), sec_data->tmp_data->smp_buf.payload,
			sizeof(sec_data->tmp_data->smp_buf.payload), 1);
	ok = zcbor_map_start_encode(zs, 1);
	if (ok) {
		zstr.len = strlen(LCZ_PKI_AUTH_MGMT_SESSION_ID_STR);
		zstr.value = LCZ_PKI_AUTH_MGMT_SESSION_ID_STR;
		ok = zcbor_tstr_encode(zs, &zstr);
	}
	if (ok) {
		ok = zcbor_uint64_encode(zs, &(sec_data->session_id));
	}
	if (ok) {
		zstr.len = strlen(LCZ_PKI_AUTH_MGMT_VERIFY_STR);
		zstr.value = LCZ_PKI_AUTH_MGMT_VERIFY_STR;
		ok = zcbor_tstr_encode(zs, &zstr);
	}
	if (ok) {
		zstr.len = sizeof(sec_data->tmp_data->verify_bytes);
		zstr.value = sec_data->tmp_data->verify_bytes;
		ok = zcbor_bstr_encode(zs, &zstr);
	}
	if (ok) {
		ok = zcbor_map_end_encode(zs, 1);
	}

	payload_len = (size_t)(zs[0].payload - sec_data->tmp_data->smp_buf.payload);

	/* Fill in SMP message header */
	sec_data->tmp_data->smp_buf.header.op = MGMT_OP_WRITE;
	sec_data->tmp_data->smp_buf.header.flags = 0;
	sec_data->tmp_data->smp_buf.header.len_h8 = (uint8_t)((payload_len >> 8) & 0xFF);
	sec_data->tmp_data->smp_buf.header.len_l8 = (uint8_t)((payload_len >> 0) & 0xFF);
	sec_data->tmp_data->smp_buf.header.group_h8 =
		(uint8_t)((CONFIG_LCZ_PKI_AUTH_SMP_GROUP_ID >> 8) & 0xFF);
	sec_data->tmp_data->smp_buf.header.group_l8 =
		(uint8_t)((CONFIG_LCZ_PKI_AUTH_SMP_GROUP_ID >> 0) & 0xFF);
	sec_data->tmp_data->smp_buf.header.seq = 0;
	sec_data->tmp_data->smp_buf.header.id = LCZ_PKI_AUTH_MGMT_ID_AUTH_VERIFY;

	if (ok) {
		ret = bt_dfu_smp_command(sec_data->tmp_data->smp_client, smp_client_resp_handler,
					 sizeof(sec_data->tmp_data->smp_buf.header) + payload_len,
					 &(sec_data->tmp_data->smp_buf));
		if (ret != 0) {
			LOG_ERR("Failed to send auth verify message: %d", ret);
		}
	} else {
		LOG_ERR("Failed to encode auth verify message");
		ret = -ENOMEM;
	}

	return ret;
}

static int send_status_message(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data)
{
	zcbor_state_t zs[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];
	struct zcbor_string zstr;
	bool ok;
	uint16_t payload_len;
	int ret;
	uint32_t status;

	/* Build the CBOR message */
	zcbor_new_state(zs, sizeof(zs) / sizeof(zs[0]), sec_data->tmp_data->smp_buf.payload,
			sizeof(sec_data->tmp_data->smp_buf.payload), 1);
	ok = zcbor_map_start_encode(zs, 1);
	if (ok) {
		zstr.len = strlen(LCZ_PKI_AUTH_MGMT_SESSION_ID_STR);
		zstr.value = LCZ_PKI_AUTH_MGMT_SESSION_ID_STR;
		ok = zcbor_tstr_encode(zs, &zstr);
	}
	if (ok) {
		ok = zcbor_uint64_encode(zs, &(sec_data->session_id));
	}
	if (ok) {
		zstr.len = strlen(LCZ_PKI_AUTH_MGMT_STATUS_STR);
		zstr.value = LCZ_PKI_AUTH_MGMT_STATUS_STR;
		ok = zcbor_tstr_encode(zs, &zstr);
	}
	if (ok) {
		/* Always send good status */
		status = LCZ_PKI_AUTH_SMP_STATUS_GOOD;
		ok = zcbor_uint32_encode(zs, &status);
	}
	if (ok) {
		ok = zcbor_map_end_encode(zs, 1);
	}

	payload_len = (size_t)(zs[0].payload - sec_data->tmp_data->smp_buf.payload);

	/* Fill in SMP message header */
	sec_data->tmp_data->smp_buf.header.op = MGMT_OP_WRITE;
	sec_data->tmp_data->smp_buf.header.flags = 0;
	sec_data->tmp_data->smp_buf.header.len_h8 = (uint8_t)((payload_len >> 8) & 0xFF);
	sec_data->tmp_data->smp_buf.header.len_l8 = (uint8_t)((payload_len >> 0) & 0xFF);
	sec_data->tmp_data->smp_buf.header.group_h8 =
		(uint8_t)((CONFIG_LCZ_PKI_AUTH_SMP_GROUP_ID >> 8) & 0xFF);
	sec_data->tmp_data->smp_buf.header.group_l8 =
		(uint8_t)((CONFIG_LCZ_PKI_AUTH_SMP_GROUP_ID >> 0) & 0xFF);
	sec_data->tmp_data->smp_buf.header.seq = 0;
	sec_data->tmp_data->smp_buf.header.id = LCZ_PKI_AUTH_MGMT_ID_AUTH_STATUS;

	if (ok) {
		ret = bt_dfu_smp_command(sec_data->tmp_data->smp_client, smp_client_resp_handler,
					 sizeof(sec_data->tmp_data->smp_buf.header) + payload_len,
					 &(sec_data->tmp_data->smp_buf));
		if (ret != 0) {
			LOG_ERR("Failed to send auth status message: %d", ret);
		}
	} else {
		LOG_ERR("Failed to encode auth status message");
		ret = -ENOMEM;
	}

	return ret;
}

static void sensor_work_handler(struct k_work *work)
{
	LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data =
		CONTAINER_OF(work, LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T, sensor_work);
	int ret = -EINVAL;

	if (sec_data->tmp_data != NULL) {
		switch (sec_data->tmp_data->state) {
		case LCZ_PKI_AUTH_CENTRAL_STATE_START:
			ret = send_start_message(sec_data);
			break;
		case LCZ_PKI_AUTH_CENTRAL_STATE_RESUME:
			ret = send_resume_message(sec_data);
			break;
		case LCZ_PKI_AUTH_CENTRAL_STATE_VERIFY:
			ret = send_verify_message(sec_data);
			break;
		case LCZ_PKI_AUTH_CENTRAL_STATE_STATUS:
			ret = send_status_message(sec_data);
			break;
		}

		if (ret != 0) {
			LOG_ERR("sensor_work_handler: Error in message sender (state %d): %d",
				sec_data->tmp_data->state, ret);

			/* Inform the application(s) that authentication failed */
			auth_status_callback(sec_data);

			/* Reset any authentication state back to defaults */
			reset_tmp_data(sec_data, true, true);
			reset_auth_data(sec_data, true, true);
		}
	}
}

static void handle_start_response(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, zcbor_state_t *zsd)
{
	uint64_t session_id;
	struct zcbor_string sensor_cert_str = { 0 };
	struct zcbor_string sensor_random = { 0 };
	size_t output_len;
	bool ok;
	int ret;
	uint32_t ver_flags = 0;
	mbedtls_pk_context priv_key;
	const mbedtls_ecp_keypair *ec;
	unsigned char q[MBEDTLS_ECP_MAX_PT_LEN];
	size_t q_len;
	psa_key_id_t priv_key_id = PSA_KEY_HANDLE_INIT;
	uint8_t raw_key_data[PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE];
	psa_key_attributes_t key_attr;
	psa_key_derivation_operation_t deriv_op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_mac_operation_t mac_op = PSA_MAC_OPERATION_INIT;

	struct zcbor_map_decode_key_val auth_start_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(id, zcbor_uint64_decode, &session_id),
		ZCBOR_MAP_DECODE_KEY_VAL(cert, zcbor_bstr_decode, &sensor_cert_str),
		ZCBOR_MAP_DECODE_KEY_VAL(rand, zcbor_bstr_decode, &sensor_random),
	};

	/* Initialize the mbedtls data structures we're using */
	mbedtls_pk_init(&priv_key);

	/*
	 * Capture the hash of the input before decoding the message.
     *
     * NOTE: The sensor code that calculates the same handshake hash does not have
     * access to the final byte of the CBOR-encoded message (the "end map"), so we
     * only compute the hash for everything up to that last byte.
     */
	ret = psa_hash_update(&(sec_data->tmp_data->hash_op), zsd->payload,
			      zsd->payload_end - zsd->payload - 1);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Failed add sensor data to hash: %d", ret);
		goto fail;
	}
	ret = psa_hash_finish(&(sec_data->tmp_data->hash_op),
			      sec_data->tmp_data->auth_handshake_hash,
			      sizeof(sec_data->tmp_data->auth_handshake_hash), &output_len);
	if (ret != PSA_SUCCESS || output_len != sizeof(sec_data->tmp_data->auth_handshake_hash)) {
		LOG_ERR("handle_start_response: Failed to compute hash: %d", ret);
		goto fail;
	}

	/* Parse the input */
	ok = zcbor_map_decode_bulk(zsd, auth_start_decode, ARRAY_SIZE(auth_start_decode),
				   &output_len) == 0;
	if (!ok || session_id != sec_data->session_id || sensor_cert_str.len == 0 ||
	    sensor_random.len != LCZ_PKI_AUTH_RAND_LEN) {
		LOG_ERR("handle_start_response: Invalid input data");
		goto fail;
	}

	/* Get the CA certificate */
	ret = lcz_pki_auth_get_ca(LCZ_PKI_AUTH_STORE_PEER_TO_PEER, &(sec_data->tmp_data->ca_cert));
	if (ret != 0) {
		LOG_ERR("handle_start_response: Could not get P2P CA certificate: %d", ret);
		goto fail;
	}

	/* Parse the sensor certificate */
	ret = mbedtls_x509_crt_parse_der_nocopy(&(sec_data->tmp_data->peripheral_cert),
						sensor_cert_str.value, sensor_cert_str.len);
	if (ret != 0) {
		LOG_ERR("handle_start_response: Could not parse sensor certificate: %d", ret);
		goto fail;
	}

	/* Validate the sensor certificate against the CA */
	ret = mbedtls_x509_crt_verify(&(sec_data->tmp_data->peripheral_cert),
				      &(sec_data->tmp_data->ca_cert), NULL, NULL, &ver_flags, NULL,
				      NULL);
	if (ret < 0) {
		LOG_ERR("handle_start_response: Could not verify sensor certificate: %d %08x", ret,
			ver_flags);
		goto fail;
	}

	/* Extract the sensor public key */
	ec = mbedtls_pk_ec(sec_data->tmp_data->peripheral_cert.pk);
	ret = mbedtls_ecp_point_write_binary(&ec->private_grp, &ec->private_Q,
					     MBEDTLS_ECP_PF_UNCOMPRESSED, &output_len, q,
					     sizeof(q));
	if (ret != 0) {
		LOG_ERR("handle_start_response: Could not extract sensor public key: %d", ret);
		goto fail;
	}
	q_len = output_len;

	/* Read our private key */
	ret = lcz_pki_auth_get_priv_key(LCZ_PKI_AUTH_STORE_PEER_TO_PEER, &priv_key);
	if (ret < 0) {
		LOG_ERR("handle_start_response: Could not get private key: %d", ret);
		goto fail;
	}
	ret = lcz_pki_auth_pk_to_psa_key(&priv_key, &priv_key_id);
	if (ret < 0) {
		LOG_ERR("handle_start_response: Could not convert private key: %d", ret);
		goto fail;
	}

	/* Raw key agreement (sensor public, our private) -> Secret key */
	ret = psa_raw_key_agreement(PSA_ALG_ECDH, priv_key_id, q, q_len, raw_key_data,
				    sizeof(raw_key_data), &output_len);
	if (ret != 0) {
		LOG_ERR("handle_start_response: Could not derive secret key: %d", ret);
		goto fail;
	}

	/* Convert raw key into PSA key */
	key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&key_attr, PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256));
	psa_set_key_type(&key_attr, PSA_KEY_TYPE_DERIVE);
	psa_set_key_bits(&key_attr, PSA_BYTES_TO_BITS(output_len));
	ret = psa_import_key(&key_attr, raw_key_data, output_len, &(sec_data->secret_key));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Failed to import secret key: %d", ret);
		goto fail;
	}
	psa_reset_key_attributes(&key_attr);
	memset(raw_key_data, 0, sizeof(raw_key_data));

	/* Set up the key derivation */
	ret = psa_key_derivation_setup(&deriv_op, PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Derivation start failed: %d", ret);
		goto fail;
	}

	/* Input the random numbers */
	memcpy(sec_data->tmp_data->random_seed + LCZ_PKI_AUTH_RAND_LEN, sensor_random.value,
	       LCZ_PKI_AUTH_RAND_LEN);
	ret = psa_key_derivation_input_bytes(&deriv_op, PSA_KEY_DERIVATION_INPUT_SEED,
					     sec_data->tmp_data->random_seed,
					     sizeof(sec_data->tmp_data->random_seed));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Could not set derivation input seed: %d", ret);
		goto fail;
	}

	/* Input the secret key */
	ret = psa_key_derivation_input_key(&deriv_op, PSA_KEY_DERIVATION_INPUT_SECRET,
					   sec_data->secret_key);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Could not set derivation input key: %d", ret);
		goto fail;
	}

	/* Input the label */
	ret = psa_key_derivation_input_bytes(&deriv_op, PSA_KEY_DERIVATION_INPUT_LABEL,
					     LCZ_PKI_AUTH_KEY_DERIV_LABEL,
					     strlen(LCZ_PKI_AUTH_KEY_DERIV_LABEL));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Could not set derivation label: %d", ret);
		goto fail;
	}

	/* Retrieve the session key(s) */
	key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_ENC_KEY_ALG);
	psa_set_key_type(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE);
	psa_set_key_bits(&key_attr, PSA_BYTES_TO_BITS(LCZ_PKI_AUTH_SMP_SESSION_KEY_LEN));
	ret = psa_key_derivation_output_key(&key_attr, &deriv_op, &(sec_data->session_enc_key));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Failed to retrieve derived encryption key: %d",
			ret);
		goto fail;
	}
	psa_reset_key_attributes(&key_attr);

	key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&key_attr,
				PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_SIG_KEY_ALG);
	psa_set_key_type(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE);
	psa_set_key_bits(&key_attr, PSA_BYTES_TO_BITS(LCZ_PKI_AUTH_SMP_SESSION_KEY_LEN));
	ret = psa_key_derivation_output_key(&key_attr, &deriv_op, &(sec_data->session_sig_key));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Failed to retrieve derived signing key: %d", ret);
		goto fail;
	}
	psa_reset_key_attributes(&key_attr);

	/* Clean up the key derivation operation */
	ret = psa_key_derivation_abort(&deriv_op);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Key derivation abort failed: %d", ret);
		goto fail;
	}

	/* Compute the gateway verify response */

	ret = psa_mac_sign_setup(&mac_op, sec_data->session_sig_key, PSA_ALG_CMAC);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Gateway verify setup failed: %d", ret);
		goto fail;
	}

	/* Input the label */
	ret = psa_mac_update(&mac_op, LCZ_PKI_AUTH_VERIFY_GATEWAY_LABEL,
			     strlen(LCZ_PKI_AUTH_VERIFY_GATEWAY_LABEL));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Could not add label to gateway verify: %d", ret);
		goto fail;
	}

	/* Input the hash */
	ret = psa_mac_update(&mac_op, sec_data->tmp_data->auth_handshake_hash,
			     sizeof(sec_data->tmp_data->auth_handshake_hash));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Could not add hash to gateway verify: %d", ret);
		goto fail;
	}

	/* Get the output */
	ret = psa_mac_sign_finish(&mac_op, sec_data->tmp_data->verify_bytes,
				  sizeof(sec_data->tmp_data->verify_bytes), &output_len);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_start_response: Could not fetch gateway verify: %d", ret);
		goto fail;
	}

	/* Send the verify message */
	sec_data->tmp_data->state = LCZ_PKI_AUTH_CENTRAL_STATE_VERIFY;
	k_work_submit(&(sec_data->sensor_work));

	/* Clean up the memory that we used locally */
	mbedtls_pk_free(&priv_key);
	psa_destroy_key(priv_key_id);
	return;

fail:
	/* Inform the application(s) that authentication failed */
	auth_status_callback(sec_data);

	/* Reset any authentication state back to defaults */
	reset_tmp_data(sec_data, true, true);
	reset_auth_data(sec_data, true, true);

	/* Clean up the memory that we used locally */
	mbedtls_pk_free(&priv_key);
	psa_destroy_key(priv_key_id);
	psa_key_derivation_abort(&deriv_op);
	psa_mac_abort(&mac_op);
}

static void handle_resume_response(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, zcbor_state_t *zsd)
{
	bool ok;
	int ret;
	struct zcbor_string sensor_random = { 0 };
	uint64_t session_id = 0;
	size_t output_len;
	psa_key_derivation_operation_t deriv_op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_key_attributes_t key_attr;
	psa_mac_operation_t mac_op = PSA_MAC_OPERATION_INIT;

	struct zcbor_map_decode_key_val auth_resume_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(id, zcbor_uint64_decode, &session_id),
		ZCBOR_MAP_DECODE_KEY_VAL(rand, zcbor_bstr_decode, &sensor_random),
	};

	/*
	 * Capture the hash of the input before decoding the message.
     *
     * NOTE: The sensor code that calculates the same handshake hash does not have
     * access to the final byte of the CBOR-encoded message (the "end map"), so we
     * only compute the hash for everything up to that last byte.
     */
	ret = psa_hash_update(&(sec_data->tmp_data->hash_op), zsd->payload,
			      zsd->payload_end - zsd->payload - 1);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Failed add sensor data to hash: %d", ret);
		goto fail;
	}
	ret = psa_hash_finish(&(sec_data->tmp_data->hash_op),
			      sec_data->tmp_data->auth_handshake_hash,
			      sizeof(sec_data->tmp_data->auth_handshake_hash), &output_len);
	if (ret != PSA_SUCCESS || output_len != sizeof(sec_data->tmp_data->auth_handshake_hash)) {
		LOG_ERR("handle_resume_response: Failed to compute hash: %d", ret);
		goto fail;
	}

	/* Parse the input */
	ok = zcbor_map_decode_bulk(zsd, auth_resume_decode, ARRAY_SIZE(auth_resume_decode),
				   &output_len) == 0;
	if (!ok || session_id != sec_data->session_id ||
	    sensor_random.len != LCZ_PKI_AUTH_RAND_LEN) {
		LOG_ERR("handle_resume_response: Invalid input data");
		goto fail;
	}

	/* Set up the key derivation */
	ret = psa_key_derivation_setup(&deriv_op, PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Derivation start failed: %d", ret);
		goto fail;
	}

	/* Input the random numbers */
	memcpy(sec_data->tmp_data->random_seed + LCZ_PKI_AUTH_RAND_LEN, sensor_random.value,
	       LCZ_PKI_AUTH_RAND_LEN);
	ret = psa_key_derivation_input_bytes(&deriv_op, PSA_KEY_DERIVATION_INPUT_SEED,
					     sec_data->tmp_data->random_seed,
					     sizeof(sec_data->tmp_data->random_seed));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Could not set derivation input seed: %d", ret);
		goto fail;
	}

	/* Input the secret key */
	ret = psa_key_derivation_input_key(&deriv_op, PSA_KEY_DERIVATION_INPUT_SECRET,
					   sec_data->secret_key);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Could not set derivation input key: %d", ret);
		goto fail;
	}

	/* Input the label */
	ret = psa_key_derivation_input_bytes(&deriv_op, PSA_KEY_DERIVATION_INPUT_LABEL,
					     LCZ_PKI_AUTH_KEY_DERIV_LABEL,
					     strlen(LCZ_PKI_AUTH_KEY_DERIV_LABEL));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Could not set derivation label: %d", ret);
		goto fail;
	}

	/* Retrieve the session keys */
	key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_ENC_KEY_ALG);
	psa_set_key_type(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE);
	psa_set_key_bits(&key_attr, PSA_BYTES_TO_BITS(LCZ_PKI_AUTH_SMP_SESSION_KEY_LEN));
	ret = psa_key_derivation_output_key(&key_attr, &deriv_op, &(sec_data->session_enc_key));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Failed to retrieve derived encryption key: %d",
			ret);
		goto fail;
	}
	psa_reset_key_attributes(&key_attr);

	key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&key_attr,
				PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_SIG_KEY_ALG);
	psa_set_key_type(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE);
	psa_set_key_bits(&key_attr, PSA_BYTES_TO_BITS(LCZ_PKI_AUTH_SMP_SESSION_KEY_LEN));
	ret = psa_key_derivation_output_key(&key_attr, &deriv_op, &(sec_data->session_sig_key));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Failed to retrieve derived signing key: %d", ret);
		goto fail;
	}
	psa_reset_key_attributes(&key_attr);

	/* Clean up the key derivation operation */
	ret = psa_key_derivation_abort(&deriv_op);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Key derivation abort failed: %d", ret);
		goto fail;
	}

	/* Compute the gateway verify response */

	ret = psa_mac_sign_setup(&mac_op, sec_data->session_sig_key, PSA_ALG_CMAC);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Gateway verify setup failed: %d", ret);
		goto fail;
	}

	/* Input the label */
	ret = psa_mac_update(&mac_op, LCZ_PKI_AUTH_VERIFY_GATEWAY_LABEL,
			     strlen(LCZ_PKI_AUTH_VERIFY_GATEWAY_LABEL));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Could not add label to gateway verify: %d", ret);
		goto fail;
	}

	/* Input the hash */
	ret = psa_mac_update(&mac_op, sec_data->tmp_data->auth_handshake_hash,
			     sizeof(sec_data->tmp_data->auth_handshake_hash));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Could not add hash to gateway verify: %d", ret);
		goto fail;
	}

	/* Get the output */
	ret = psa_mac_sign_finish(&mac_op, sec_data->tmp_data->verify_bytes,
				  sizeof(sec_data->tmp_data->verify_bytes), &output_len);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_resume_response: Could not fetch gateway verify: %d", ret);
		goto fail;
	}

	/* Send the verify message */
	sec_data->tmp_data->state = LCZ_PKI_AUTH_CENTRAL_STATE_VERIFY;
	k_work_submit(&(sec_data->sensor_work));

	return;

fail:
	/* Reset any authentication state back to defaults */
	reset_tmp_data(sec_data, true, true);
	reset_auth_data(sec_data, true, true);

	/* Clean up the memory that we used locally */
	psa_key_derivation_abort(&deriv_op);
	psa_mac_abort(&mac_op);

	/* This was a resume attempt that failed, so start from scratch */
	ret = session_start(sec_data);
	if (ret != 0) {
		/* Inform the application(s) that authentication failed */
		auth_status_callback(sec_data);
	}
}

static void handle_verify_response(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, zcbor_state_t *zsd)
{
	bool ok;
	int ret;
	struct zcbor_string sensor_verify = { 0 };
	uint64_t session_id = 0;
	size_t output_len;
	psa_mac_operation_t mac_op = PSA_MAC_OPERATION_INIT;

	struct zcbor_map_decode_key_val auth_verify_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(id, zcbor_uint64_decode, &session_id),
		ZCBOR_MAP_DECODE_KEY_VAL(v, zcbor_bstr_decode, &sensor_verify),
	};

	/* Parse the input */
	ok = zcbor_map_decode_bulk(zsd, auth_verify_decode, ARRAY_SIZE(auth_verify_decode),
				   &output_len) == 0;
	if (!ok || session_id != sec_data->session_id ||
	    sensor_verify.len != LCZ_PKI_AUTH_SMP_VERIFY_LEN) {
		LOG_ERR("handle_verify_response: Invalid input data");
		goto fail;
	}

	/* Compute the sensors verify expected response */

	ret = psa_mac_verify_setup(&mac_op, sec_data->session_sig_key, PSA_ALG_CMAC);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_verify_response: Sensor verify setup failed: %d", ret);
		goto fail;
	}

	/* Input the label */
	ret = psa_mac_update(&mac_op, LCZ_PKI_AUTH_VERIFY_SENSOR_LABEL,
			     strlen(LCZ_PKI_AUTH_VERIFY_SENSOR_LABEL));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_verify_response: Could not add label to sensor verify: %d", ret);
		goto fail;
	}

	/* Input the hash */
	ret = psa_mac_update(&mac_op, sec_data->tmp_data->auth_handshake_hash,
			     sizeof(sec_data->tmp_data->auth_handshake_hash));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_verify_response: Could not add hash to sensor verify: %d", ret);
		goto fail;
	}

	/* Compare with the sensor's value */
	ret = psa_mac_verify_finish(&mac_op, sensor_verify.value, sensor_verify.len);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("handle_verify_response: Could not verify sensor value: %d", ret);
		goto fail;
	}

	/* Send the status message */
	sec_data->tmp_data->state = LCZ_PKI_AUTH_CENTRAL_STATE_STATUS;
	k_work_submit(&(sec_data->sensor_work));

	return;

fail:
	/* Clean up the memory that we used locally */
	psa_mac_abort(&mac_op);

	/* If this was a resume attempt, start over fresh */
	if (sec_data->status == LCZ_PKI_AUTH_SMP_STATUS_GOOD) {
		/* Reset any authentication state back to defaults */
		reset_tmp_data(sec_data, true, true);
		reset_auth_data(sec_data, true, true);

		/* This was a resume attempt that failed, so start from scratch */
		ret = session_start(sec_data);
		if (ret != 0) {
			/* Inform the application(s) that authentication failed */
			auth_status_callback(sec_data);
		}
	} else {
		/* Inform the application(s) that authentication failed */
		sec_data->status = 0;
		auth_status_callback(sec_data);

		/* Reset any authentication state back to defaults */
		reset_tmp_data(sec_data, true, true);
		reset_auth_data(sec_data, true, true);
	}
}

static void handle_status_response(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data, zcbor_state_t *zsd)
{
	bool ok;
	uint64_t session_id = 0;
	uint32_t auth_status = 0;
	size_t output_len = 0;
	int ret;

	struct zcbor_map_decode_key_val auth_status_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(id, zcbor_uint64_decode, &session_id),
		ZCBOR_MAP_DECODE_KEY_VAL(status, zcbor_uint32_decode, &auth_status),
	};

	/* Parse the input */
	ok = zcbor_map_decode_bulk(zsd, auth_status_decode, ARRAY_SIZE(auth_status_decode),
				   &output_len) == 0;
	if (!ok || session_id == 0) {
		LOG_ERR("handle_status_response: Failed to parse input message");
		goto fail;
	}

	/* Verify the input parameters */
	if (session_id != sec_data->session_id || auth_status != LCZ_PKI_AUTH_SMP_STATUS_GOOD) {
		LOG_ERR("handle_status_response: Status failed");
		goto fail;
	}

	/* Successful exchange */
	sec_data->status = LCZ_PKI_AUTH_SMP_STATUS_GOOD;

	/* If this is a session start, set the expiration time */
	if (sec_data->resumed == false) {
		sec_data->expires =
			k_uptime_get() + (CONFIG_LCZ_PKI_AUTH_SMP_SESSION_TIME * MSEC_PER_SEC);
	}

	/* Inform the application(s) that authentication succeeded */
	auth_status_callback(sec_data);

	return;

fail:
	/* If this was a resume attempt, start over fresh */
	if (sec_data->status == LCZ_PKI_AUTH_SMP_STATUS_GOOD) {
		/* Reset any authentication state back to defaults */
		reset_tmp_data(sec_data, true, true);
		reset_auth_data(sec_data, true, true);

		/* This was a resume attempt that failed, so start from scratch */
		ret = session_start(sec_data);
		if (ret != 0) {
			/* Inform the application(s) that authentication failed */
			auth_status_callback(sec_data);
		}
	} else {
		/* Inform the application(s) that authentication failed */
		sec_data->status = 0;
		auth_status_callback(sec_data);

		/* Reset any authentication state back to defaults */
		reset_tmp_data(sec_data, true, true);
		reset_auth_data(sec_data, true, true);
	}
}

/** @brief Handler for a received SMP message from the peripheral
 *
 * @param[in] dfu_smp DFU SMP client structure pointer
 */
static void smp_client_resp_handler(struct bt_dfu_smp *dfu_smp)
{
	LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data;
	int obj_idx;
	uint8_t *p_outdata;
	const struct bt_dfu_smp_rsp_state *rsp_state;
	zcbor_state_t states[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];
	uint16_t payload_len;
	int ret = 0;

	/* Look up device in gateway database */
	obj_idx = lcz_lwm2m_gw_obj_lookup_ble(bt_conn_get_dst(bt_dfu_smp_conn(dfu_smp)));
	if (obj_idx < 0) {
		/* This isn't a device we know about. Do nothing. */
		return;
	}

	/* Retrieve the security data for the device */
	sec_data = (LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *)lcz_lwm2m_gw_obj_get_security_data(obj_idx);
	if (sec_data == NULL || sec_data->tmp_data == NULL) {
		LOG_ERR("smp_client_resp_handler: Security data not allocated");
		ret = -ENOMEM;
	}

	if (ret == 0) {
		/* Get the current response state */
		rsp_state = bt_dfu_smp_rsp_state(dfu_smp);

		/* Copy the new data in our response buffer */
		if (rsp_state->offset + rsp_state->chunk_size >
		    sizeof(sec_data->tmp_data->smp_buf)) {
			LOG_ERR("Response size buffer overflow");
			ret = -ENOMEM;
		} else {
			p_outdata = (uint8_t *)&(sec_data->tmp_data->smp_buf);
			p_outdata += rsp_state->offset;
			memcpy(p_outdata, rsp_state->data, rsp_state->chunk_size);
		}
	}

	/* Check to see if that was the end of the message */
	if (ret == 0) {
		if (!bt_dfu_smp_rsp_total_check(dfu_smp)) {
			/* This is not an error specifically. We just need to wait for more data. */
			ret = -EAGAIN;
		}
	}

	/* Verify the group ID in the message */
	if (ret == 0) {
		uint16_t group = ((uint16_t)sec_data->tmp_data->smp_buf.header.group_h8) << 8 |
				 sec_data->tmp_data->smp_buf.header.group_l8;
		if (group != CONFIG_LCZ_PKI_AUTH_SMP_GROUP_ID) {
			LOG_ERR("SMP response has wrong group");
			ret = -EINVAL;
		}
	}

	/* Handle the write response */
	if (ret == 0 && sec_data->tmp_data->smp_buf.header.op == MGMT_OP_WRITE_RSP) {
		payload_len = ((uint16_t)sec_data->tmp_data->smp_buf.header.len_h8) << 8 |
			      sec_data->tmp_data->smp_buf.header.len_l8;

		/* Initialize the CBOR reader */
		zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t),
				sec_data->tmp_data->smp_buf.payload, payload_len, 1);

		switch (sec_data->tmp_data->smp_buf.header.id) {
		case LCZ_PKI_AUTH_MGMT_ID_AUTH_START:
			handle_start_response(sec_data, states);
			break;
		case LCZ_PKI_AUTH_MGMT_ID_AUTH_RESUME:
			handle_resume_response(sec_data, states);
			break;
		case LCZ_PKI_AUTH_MGMT_ID_AUTH_VERIFY:
			handle_verify_response(sec_data, states);
			break;
		case LCZ_PKI_AUTH_MGMT_ID_AUTH_STATUS:
			handle_status_response(sec_data, states);
			break;
		}
	}

	/* Any other operations are errors */
	else if (ret == 0) {
		LOG_ERR("Invalid SMP operation %d", sec_data->tmp_data->smp_buf.header.op);
	}
}

static int session_start(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data)
{
	int ret = 0;

	/* Get our device certificate */
	ret = lcz_pki_auth_get_dev_cert(LCZ_PKI_AUTH_STORE_PEER_TO_PEER,
					&(sec_data->tmp_data->gateway_cert));
	if (ret != 0) {
		LOG_ERR("session_start: Could not get P2P device certificate: %d", ret);
		goto fail;
	}

	/* Generate gateway random number */
	ret = psa_generate_random(sec_data->tmp_data->random_seed, LCZ_PKI_AUTH_RAND_LEN);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("session_start: Could not generate gateway random number: %d", ret);
		goto fail;
	}

	/* Generate session number */
	ret = psa_generate_random((uint8_t *)&(sec_data->session_id), sizeof(sec_data->session_id));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("session_start: Could not generate random session ID: %d", ret);
		goto fail;
	}

	/* Send the start message */
	sec_data->resumed = false;
	sec_data->tmp_data->state = LCZ_PKI_AUTH_CENTRAL_STATE_START;
	k_work_submit(&(sec_data->sensor_work));
	return 0;

fail:
	/* Inform the application(s) that authentication failed */
	auth_status_callback(sec_data);

	/* Reset any authentication state back to defaults */
	reset_tmp_data(sec_data, true, true);
	reset_auth_data(sec_data, true, true);

	return ret;
}

static int session_resume(LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data)
{
	int ret = 0;

	/* Destroy existing session keys that we will re-create */
	psa_destroy_key(sec_data->session_enc_key);
	sec_data->session_enc_key = PSA_KEY_HANDLE_INIT;
	psa_destroy_key(sec_data->session_sig_key);
	sec_data->session_sig_key = PSA_KEY_HANDLE_INIT;

	/* Generate gateway random number */
	ret = psa_generate_random(sec_data->tmp_data->random_seed, LCZ_PKI_AUTH_RAND_LEN);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("session_resume: Could not generate gateway random number: %d", ret);
		goto fail;
	}

	/* Send the resume message */
	sec_data->resumed = true;
	sec_data->tmp_data->state = LCZ_PKI_AUTH_CENTRAL_STATE_RESUME;
	k_work_submit(&(sec_data->sensor_work));
	return 0;

fail:
	/* Inform the application(s) that authentication failed */
	auth_status_callback(sec_data);

	/* Reset any authentication state back to defaults */
	reset_tmp_data(sec_data, true, true);
	reset_auth_data(sec_data, true, true);

	return ret;
}

static void device_deleted_cb(int idx, void *data_ptr)
{
	LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data = (LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *)data_ptr;
	clean_up_data(idx, sec_data);
}

static void auth_timeout_handler(struct k_work *work)
{
	LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T *sec_data =
		CONTAINER_OF(work, LCZ_PKI_AUTH_SMP_CENTRAL_DATA_T, timeout_work);

	/* Inform the application(s) that authentication failed */
	sec_data->status = 0;
	auth_status_callback(sec_data);

	/* Reset any authentication state back to defaults */
	reset_tmp_data(sec_data, true, true);
	reset_auth_data(sec_data, true, true);
}

/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
SYS_INIT(lcz_pki_auth_smp_central_init, APPLICATION, CONFIG_LCZ_PKI_AUTH_SMP_INIT_PRIORITY);
static int lcz_pki_auth_smp_central_init(const struct device *dev)
{
	ARG_UNUSED(dev);

	/* Register for BT callbacks */
	bt_conn_cb_register(&conn_callbacks);

	/* Register for object deleted notifications */
	lcz_lwm2m_gw_obj_set_security_delete_cb(device_deleted_cb);

	return 0;
}
