/**
 * @file lcz_pki_auth_smp_periph.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_pki_auth_smp_periph, CONFIG_LCZ_PKI_AUTH_LOG_LEVEL);

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

#include "lcz_pki_auth.h"
#include "lcz_pki_auth_smp.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
typedef struct {
	uint8_t sensor_random[LCZ_PKI_AUTH_RAND_LEN];
	psa_hash_operation_t hash_op;
	psa_key_id_t priv_key_id;
	mbedtls_pk_context priv_key;
	const mbedtls_ecp_keypair *ec;
	unsigned char q[MBEDTLS_ECP_MAX_PT_LEN];
	mbedtls_x509_crt ca_cert;
	mbedtls_x509_crt device_cert;
	mbedtls_x509_crt gateway_cert;
	psa_key_derivation_operation_t deriv_op;
	uint8_t raw_key_data[PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE];
	uint8_t random_seed[LCZ_PKI_AUTH_RAND_LEN * 2];
	psa_key_attributes_t key_attr;
} LCZ_PKI_AUTH_SMP_START_DATA_T;

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_pki_auth_smp_periph_init(const struct device *dev);

static void auth_data_reset(void);

static int smp_cmd_auth_start(struct mgmt_ctxt *ctxt);
static int smp_cmd_auth_resume(struct mgmt_ctxt *ctxt);
static int smp_cmd_auth_verify(struct mgmt_ctxt *ctxt);
static int smp_cmd_auth_status(struct mgmt_ctxt *ctxt);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static const struct mgmt_handler lcz_pki_mgmt_handlers[] = {
    [LCZ_PKI_AUTH_MGMT_ID_AUTH_START] = {
        .mh_read = NULL,
        .mh_write = smp_cmd_auth_start,
    },
    [LCZ_PKI_AUTH_MGMT_ID_AUTH_RESUME] = {
        .mh_read = NULL,
        .mh_write = smp_cmd_auth_resume,
    },
    [LCZ_PKI_AUTH_MGMT_ID_AUTH_VERIFY] = {
        .mh_read = NULL,
        .mh_write = smp_cmd_auth_verify,
    },
    [LCZ_PKI_AUTH_MGMT_ID_AUTH_STATUS] = {
        .mh_read = NULL,
        .mh_write = smp_cmd_auth_status,
    },
};

static struct mgmt_group lcz_pki_mgmt_group = {
	.mg_handlers = lcz_pki_mgmt_handlers,
	.mg_handlers_count = (sizeof(lcz_pki_mgmt_handlers) / sizeof(lcz_pki_mgmt_handlers[0])),
	.mg_group_id = CONFIG_LCZ_PKI_AUTH_SMP_GROUP_ID,
};

static sys_slist_t auth_complete_cb_list = SYS_SLIST_STATIC_INIT(&auth_complete_cb_list);

static uint64_t auth_session_id = 0;
static psa_key_id_t auth_secret_key = PSA_KEY_HANDLE_INIT;
static psa_key_id_t auth_session_aead_key = PSA_KEY_HANDLE_INIT;
static psa_key_id_t auth_session_enc_key = PSA_KEY_HANDLE_INIT;
static psa_key_id_t auth_session_sig_key = PSA_KEY_HANDLE_INIT;
static uint8_t auth_handshake_hash[LCZ_PKI_AUTH_SMP_HANDSHAKE_HASH_LEN];
static uint32_t auth_status = 0;

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
void lcz_pki_auth_smp_periph_register_handler(struct lcz_pki_auth_smp_periph_auth_callback_agent *cb)
{
	sys_slist_append(&auth_complete_cb_list, &cb->node);
}

void lcz_pki_auth_smp_periph_unregister_handler(
	struct lcz_pki_auth_smp_periph_auth_callback_agent *cb)
{
	(void)sys_slist_find_and_remove(&auth_complete_cb_list, &cb->node);
}

int lcz_pki_auth_smp_periph_get_keys(psa_key_id_t *aead_key, psa_key_id_t *enc_key,
				     psa_key_id_t *sig_key)
{
	if (auth_status == LCZ_PKI_AUTH_SMP_STATUS_GOOD) {
		if (aead_key) {
			*aead_key = auth_session_aead_key;
		}
		if (enc_key) {
			*enc_key = auth_session_enc_key;
		}
		if (sig_key) {
			*sig_key = auth_session_sig_key;
		}
		return 0;
	} else {
		return -ENOENT;
	}
}

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
/**
 * @brief Call any registered callbacks with authentication status
 */
static void auth_status_callback(void)
{
	sys_snode_t *node;
	struct lcz_pki_auth_smp_periph_auth_callback_agent *agent;

	SYS_SLIST_FOR_EACH_NODE (&auth_complete_cb_list, node) {
		agent = CONTAINER_OF(node, struct lcz_pki_auth_smp_periph_auth_callback_agent,
				     node);
		if (agent->cb != NULL) {
			agent->cb((auth_status == LCZ_PKI_AUTH_SMP_STATUS_GOOD));
		}
	}
}

/**
 * @brief Reset all of the local authentication data to default states
 */
static void auth_data_reset(void)
{
	auth_session_id = 0;

	psa_destroy_key(auth_session_aead_key);
	auth_session_aead_key = PSA_KEY_HANDLE_INIT;
	psa_destroy_key(auth_session_enc_key);
	auth_session_enc_key = PSA_KEY_HANDLE_INIT;
	psa_destroy_key(auth_session_sig_key);
	auth_session_sig_key = PSA_KEY_HANDLE_INIT;
	psa_destroy_key(auth_secret_key);
	auth_secret_key = PSA_KEY_HANDLE_INIT;

	memset(auth_handshake_hash, 0, sizeof(auth_handshake_hash));
	auth_status = 0;
	auth_status_callback();
}

static int smp_cmd_auth_start(struct mgmt_ctxt *ctxt)
{
	bool ok;
	int ret;
	zcbor_state_t *zse = ctxt->cnbe->zs;
	zcbor_state_t *zsd = ctxt->cnbd->zs;
	struct zcbor_string gateway_cert_str = { 0 };
	struct zcbor_string gateway_random = { 0 };
	uint64_t session_id = 0;
	size_t decoded = 0;
	size_t output_len;
	size_t q_len;
	uint32_t ver_flags = 0;
	LCZ_PKI_AUTH_SMP_START_DATA_T *sdata;

	struct zcbor_map_decode_key_val auth_start_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(id, zcbor_uint64_decode, &session_id),
		ZCBOR_MAP_DECODE_KEY_VAL(cert, zcbor_bstr_decode, &gateway_cert_str),
		ZCBOR_MAP_DECODE_KEY_VAL(rand, zcbor_bstr_decode, &gateway_random),
	};

	/* On start, reset any authentication state back to defaults */
	auth_data_reset();

	sdata = (LCZ_PKI_AUTH_SMP_START_DATA_T *)k_malloc(sizeof(LCZ_PKI_AUTH_SMP_START_DATA_T));
	if (sdata == NULL) {
		LOG_ERR("smp_cmd_auth_start: Could not allocate start data memory");
		return -ENOMEM;
	}

	/* Initialize the mbedtls data structures we're using */
	sdata->hash_op = psa_hash_operation_init();
	sdata->priv_key_id = PSA_KEY_HANDLE_INIT;
	sdata->deriv_op = psa_key_derivation_operation_init();
	mbedtls_pk_init(&(sdata->priv_key));
	mbedtls_x509_crt_init(&(sdata->ca_cert));
	mbedtls_x509_crt_init(&(sdata->device_cert));
	mbedtls_x509_crt_init(&(sdata->gateway_cert));

	/* Capture the hash of the input before decoding the message */
	ret = psa_hash_setup(&(sdata->hash_op), PSA_ALG_SHA_256);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Failed to initialize hash: %d", ret);
		goto fail;
	}
	ret = psa_hash_update(&(sdata->hash_op), zsd->payload, zsd->payload_end - zsd->payload);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Failed add gateway data to hash: %d", ret);
		goto fail;
	}

	/* Parse the input */
	ok = zcbor_map_decode_bulk(zsd, auth_start_decode, ARRAY_SIZE(auth_start_decode),
				   &decoded) == 0;
	if (!ok || session_id == 0 || gateway_cert_str.len == 0 ||
	    gateway_random.len != LCZ_PKI_AUTH_RAND_LEN) {
		LOG_ERR("smp_cmd_auth_start: Invalid input data");
		goto fail;
	}

	/* Save the session ID for later */
	auth_session_id = session_id;

	/* Get the CA certificate */
	ret = lcz_pki_auth_get_ca(LCZ_PKI_AUTH_STORE_PEER_TO_PEER, &(sdata->ca_cert));
	if (ret != 0) {
		LOG_ERR("smp_cmd_auth_start: Could not get P2P CA certificate: %d", ret);
		goto fail;
	}

	/* Parse the gateway certificate */
	ret = mbedtls_x509_crt_parse_der_nocopy(&(sdata->gateway_cert), gateway_cert_str.value,
						gateway_cert_str.len);
	if (ret != 0) {
		LOG_ERR("smp_cmd_auth_start: Could not parse gateway certificate: %d", ret);
		goto fail;
	}

	/* Validate the gateway certificate against the CA */
	ret = mbedtls_x509_crt_verify(&(sdata->gateway_cert), &(sdata->ca_cert), NULL, NULL,
				      &ver_flags, NULL, NULL);
	if (ret < 0) {
		LOG_ERR("smp_cmd_auth_start: Could not verify gateway certificate: %d %08x", ret,
			ver_flags);
		goto fail;
	}

	/* Extract the gateway public key */
	sdata->ec = mbedtls_pk_ec(sdata->gateway_cert.pk);
	ret = mbedtls_ecp_point_write_binary(&(sdata->ec->private_grp), &(sdata->ec->private_Q),
					     MBEDTLS_ECP_PF_UNCOMPRESSED, &output_len, sdata->q,
					     sizeof(sdata->q));
	if (ret != 0) {
		LOG_ERR("smp_cmd_auth_start: Could not extract gateway public key: %d", ret);
		goto fail;
	}
	q_len = output_len;

	/* Read our private key */
	ret = lcz_pki_auth_get_priv_key(LCZ_PKI_AUTH_STORE_PEER_TO_PEER, &(sdata->priv_key));
	if (ret < 0) {
		LOG_ERR("smp_cmd_auth_start: Could not get private key: %d", ret);
		goto fail;
	}
	ret = lcz_pki_auth_pk_to_psa_key(&(sdata->priv_key), &(sdata->priv_key_id));
	if (ret < 0) {
		LOG_ERR("smp_cmd_auth_start: Could not convert private key: %d", ret);
		goto fail;
	}

	/* Raw key agreement (gateway public, our private) -> Secret key */
	ret = psa_raw_key_agreement(PSA_ALG_ECDH, sdata->priv_key_id, sdata->q, q_len,
				    sdata->raw_key_data, sizeof(sdata->raw_key_data), &output_len);
	if (ret != 0) {
		LOG_ERR("smp_cmd_auth_start: Could not derive secret key: %d", ret);
		goto fail;
	}

	/* Convert raw key into PSA key */
	sdata->key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&(sdata->key_attr), PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&(sdata->key_attr), PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256));
	psa_set_key_type(&(sdata->key_attr), PSA_KEY_TYPE_DERIVE);
	psa_set_key_bits(&(sdata->key_attr), PSA_BYTES_TO_BITS(output_len));
	ret = psa_import_key(&(sdata->key_attr), sdata->raw_key_data, output_len, &auth_secret_key);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Failed to import secret key: %d", ret);
		goto fail;
	}
	psa_reset_key_attributes(&(sdata->key_attr));
	memset(sdata->raw_key_data, 0, sizeof(sdata->raw_key_data));

	/* Generate the sensor random number */
	ret = psa_generate_random(sdata->sensor_random, sizeof(sdata->sensor_random));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Could not generate random number: %d", ret);
		goto fail;
	}

	/* Set up the key derivation */
	ret = psa_key_derivation_setup(&(sdata->deriv_op), PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Derivation start failed: %d", ret);
		goto fail;
	}

	/* Input the random numbers */
	memcpy(sdata->random_seed, gateway_random.value, LCZ_PKI_AUTH_RAND_LEN);
	memcpy(sdata->random_seed + LCZ_PKI_AUTH_RAND_LEN, sdata->sensor_random,
	       LCZ_PKI_AUTH_RAND_LEN);
	ret = psa_key_derivation_input_bytes(&(sdata->deriv_op), PSA_KEY_DERIVATION_INPUT_SEED,
					     sdata->random_seed, sizeof(sdata->random_seed));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Could not set derivation input seed: %d", ret);
		goto fail;
	}

	/* Input the secret key */
	ret = psa_key_derivation_input_key(&(sdata->deriv_op), PSA_KEY_DERIVATION_INPUT_SECRET,
					   auth_secret_key);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Could not set derivation input key: %d", ret);
		goto fail;
	}

	/* Input the label */
	ret = psa_key_derivation_input_bytes(&(sdata->deriv_op), PSA_KEY_DERIVATION_INPUT_LABEL,
					     LCZ_PKI_AUTH_KEY_DERIV_LABEL,
					     strlen(LCZ_PKI_AUTH_KEY_DERIV_LABEL));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Could not set derivation label: %d", ret);
		goto fail;
	}

	/* Retrieve the session key */
	sdata->key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&(sdata->key_attr), PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&(sdata->key_attr), LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG);
	psa_set_key_type(&(sdata->key_attr), LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE);
	psa_set_key_bits(&(sdata->key_attr), PSA_BYTES_TO_BITS(LCZ_PKI_AUTH_SMP_SESSION_KEY_LEN));
	ret = psa_key_derivation_output_key(&(sdata->key_attr), &(sdata->deriv_op),
					    &auth_session_aead_key);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Failed to retrieve derived encryption key: %d", ret);
		goto fail;
	}
	psa_reset_key_attributes(&(sdata->key_attr));

	sdata->key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&(sdata->key_attr), PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&(sdata->key_attr), LCZ_PKI_AUTH_SMP_SESSION_ENC_KEY_ALG);
	psa_set_key_type(&(sdata->key_attr), LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE);
	psa_set_key_bits(&(sdata->key_attr), PSA_BYTES_TO_BITS(LCZ_PKI_AUTH_SMP_SESSION_KEY_LEN));
	ret = psa_key_derivation_output_key(&(sdata->key_attr), &(sdata->deriv_op),
					    &auth_session_enc_key);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Failed to retrieve derived encryption key: %d", ret);
		goto fail;
	}
	psa_reset_key_attributes(&(sdata->key_attr));

	sdata->key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&(sdata->key_attr),
				PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&(sdata->key_attr), LCZ_PKI_AUTH_SMP_SESSION_SIG_KEY_ALG);
	psa_set_key_type(&(sdata->key_attr), LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE);
	psa_set_key_bits(&(sdata->key_attr), PSA_BYTES_TO_BITS(LCZ_PKI_AUTH_SMP_SESSION_KEY_LEN));
	ret = psa_key_derivation_output_key(&(sdata->key_attr), &(sdata->deriv_op),
					    &auth_session_sig_key);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Failed to retrieve derived signing key: %d", ret);
		goto fail;
	}
	psa_reset_key_attributes(&(sdata->key_attr));

	/* Clean up the key derivation operation */
	ret = psa_key_derivation_abort(&(sdata->deriv_op));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Derivation abort failed: %d", ret);
		goto fail;
	}

	/* Get the device certificate */
	ret = lcz_pki_auth_get_dev_cert(LCZ_PKI_AUTH_STORE_PEER_TO_PEER, &(sdata->device_cert));
	if (ret != 0) {
		LOG_ERR("smp_cmd_auth_start: Could not get P2P device certificate: %d", ret);
		goto fail;
	}

	/* Build our response */
	ok = zcbor_tstr_put_lit(zse, "id") && zcbor_uint64_put(zse, auth_session_id) &&
	     zcbor_tstr_put_lit(zse, "rand") &&
	     zcbor_bstr_encode_ptr(zse, sdata->sensor_random, sizeof(sdata->sensor_random)) &&
	     zcbor_tstr_put_lit(zse, "cert") &&
	     zcbor_bstr_encode_ptr(zse, sdata->device_cert.raw.p, sdata->device_cert.raw.len);
	if (!ok) {
		LOG_ERR("smp_cmd_auth_start: Failed to encode response");
		goto fail;
	}

	/* Add our response to the hash operation */
	ret = psa_hash_update(&(sdata->hash_op), ctxt->cnbe->nb->data + 8,
			      (zse->payload_mut - ctxt->cnbe->nb->data - 8));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_start: Failed to add our payload to the hash: %d", ret);
		goto fail;
	}
	ret = psa_hash_finish(&(sdata->hash_op), auth_handshake_hash, sizeof(auth_handshake_hash),
			      &output_len);
	if (ret != PSA_SUCCESS || output_len != sizeof(auth_handshake_hash)) {
		LOG_ERR("smp_cmd_auth_start: Failed to compute hash: %d", ret);
		goto fail;
	}

	/* Clean up the memory that we used */
	mbedtls_pk_free(&(sdata->priv_key));
	psa_destroy_key(sdata->priv_key_id);
	mbedtls_x509_crt_free(&(sdata->gateway_cert));
	mbedtls_x509_crt_free(&(sdata->device_cert));
	mbedtls_x509_crt_free(&(sdata->ca_cert));
	memset(sdata, 0, sizeof(LCZ_PKI_AUTH_SMP_START_DATA_T));
	k_free(sdata);

	return MGMT_ERR_EOK;

fail:
	/* Reset any authentication state back to defaults */
	auth_data_reset();

	/* Clean up the memory that we used */
	mbedtls_pk_free(&(sdata->priv_key));
	psa_destroy_key(sdata->priv_key_id);
	mbedtls_x509_crt_free(&(sdata->gateway_cert));
	mbedtls_x509_crt_free(&(sdata->device_cert));
	mbedtls_x509_crt_free(&(sdata->ca_cert));
	psa_hash_abort((&sdata->hash_op));
	psa_key_derivation_abort(&(sdata->deriv_op));
	memset(sdata, 0, sizeof(LCZ_PKI_AUTH_SMP_START_DATA_T));
	k_free(sdata);

	return MGMT_ERR_EUNKNOWN;
}

static int smp_cmd_auth_resume(struct mgmt_ctxt *ctxt)
{
	bool ok;
	int ret;
	zcbor_state_t *zse = ctxt->cnbe->zs;
	zcbor_state_t *zsd = ctxt->cnbd->zs;
	struct zcbor_string gateway_random = { 0 };
	uint64_t session_id = 0;
	size_t decoded = 0;
	psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;
	size_t output_len;
	psa_key_derivation_operation_t deriv_op = PSA_KEY_DERIVATION_OPERATION_INIT;
	uint8_t sensor_random[LCZ_PKI_AUTH_RAND_LEN];
	uint8_t random_seed[LCZ_PKI_AUTH_RAND_LEN * 2];
	psa_key_attributes_t key_attr;

	struct zcbor_map_decode_key_val auth_resume_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(id, zcbor_uint64_decode, &session_id),
		ZCBOR_MAP_DECODE_KEY_VAL(rand, zcbor_bstr_decode, &gateway_random),
	};

	/* On resume, destroy the session keys first */
	psa_destroy_key(auth_session_aead_key);
	auth_session_aead_key = PSA_KEY_HANDLE_INIT;
	psa_destroy_key(auth_session_enc_key);
	auth_session_enc_key = PSA_KEY_HANDLE_INIT;
	psa_destroy_key(auth_session_sig_key);
	auth_session_sig_key = PSA_KEY_HANDLE_INIT;

	/* Capture the hash of the input before decoding the message */
	ret = psa_hash_setup(&hash_op, PSA_ALG_SHA_256);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Failed to initialize hash: %d", ret);
		goto fail;
	}
	ret = psa_hash_update(&hash_op, zsd->payload, zsd->payload_end - zsd->payload);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Failed add gateway data to hash: %d", ret);
		goto fail;
	}

	/* Parse the input */
	ok = zcbor_map_decode_bulk(zsd, auth_resume_decode, ARRAY_SIZE(auth_resume_decode),
				   &decoded) == 0;
	if (!ok || session_id == 0 || gateway_random.len != LCZ_PKI_AUTH_RAND_LEN) {
		LOG_ERR("smp_cmd_auth_resume: Failed to parse input message");
		goto fail;
	}

	/* Make sure that session ID matches the session that we have */
	if (session_id != auth_session_id) {
		LOG_ERR("smp_cmd_auth_resume: Session ID mismatch");
		goto fail;
	}

	/* Generate the sensor random number */
	ret = psa_generate_random(sensor_random, sizeof(sensor_random));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Could not generate random number: %d", ret);
		goto fail;
	}

	/* Set up the key derivation */
	ret = psa_key_derivation_setup(&deriv_op, PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Derivation start failed: %d", ret);
		goto fail;
	}

	/* Input the random numbers */
	memcpy(random_seed, gateway_random.value, LCZ_PKI_AUTH_RAND_LEN);
	memcpy(random_seed + LCZ_PKI_AUTH_RAND_LEN, sensor_random, LCZ_PKI_AUTH_RAND_LEN);
	ret = psa_key_derivation_input_bytes(&deriv_op, PSA_KEY_DERIVATION_INPUT_SEED, random_seed,
					     sizeof(random_seed));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Could not set derivation input seed: %d", ret);
		goto fail;
	}

	/* Input the secret key */
	ret = psa_key_derivation_input_key(&deriv_op, PSA_KEY_DERIVATION_INPUT_SECRET,
					   auth_secret_key);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Could not set derivation input key: %d", ret);
		goto fail;
	}

	/* Input the label */
	ret = psa_key_derivation_input_bytes(&deriv_op, PSA_KEY_DERIVATION_INPUT_LABEL,
					     LCZ_PKI_AUTH_KEY_DERIV_LABEL,
					     strlen(LCZ_PKI_AUTH_KEY_DERIV_LABEL));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Could not set derivation label: %d", ret);
		goto fail;
	}

	/* Retrieve the session key */
	key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG);
	psa_set_key_type(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE);
	psa_set_key_bits(&key_attr, PSA_BYTES_TO_BITS(LCZ_PKI_AUTH_SMP_SESSION_KEY_LEN));
	ret = psa_key_derivation_output_key(&key_attr, &deriv_op, &auth_session_aead_key);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Failed to retrieve derived encryption key: %d", ret);
		goto fail;
	}
	psa_reset_key_attributes(&key_attr);

	key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_ENC_KEY_ALG);
	psa_set_key_type(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE);
	psa_set_key_bits(&key_attr, PSA_BYTES_TO_BITS(LCZ_PKI_AUTH_SMP_SESSION_KEY_LEN));
	ret = psa_key_derivation_output_key(&key_attr, &deriv_op, &auth_session_enc_key);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Failed to retrieve derived encryption key: %d", ret);
		goto fail;
	}
	psa_reset_key_attributes(&key_attr);

	key_attr = psa_key_attributes_init();
	psa_set_key_usage_flags(&key_attr,
				PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_SIG_KEY_ALG);
	psa_set_key_type(&key_attr, LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE);
	psa_set_key_bits(&key_attr, PSA_BYTES_TO_BITS(LCZ_PKI_AUTH_SMP_SESSION_KEY_LEN));
	ret = psa_key_derivation_output_key(&key_attr, &deriv_op, &auth_session_sig_key);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Failed to retrieve derived signing key: %d", ret);
		goto fail;
	}
	psa_reset_key_attributes(&key_attr);

	/* Clean up the key derivation operation */
	ret = psa_key_derivation_abort(&deriv_op);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Derivation abort failed: %d", ret);
		goto fail;
	}

	/* Build our response */
	ok = zcbor_tstr_put_lit(zse, "id") && zcbor_uint64_put(zse, auth_session_id) &&
	     zcbor_tstr_put_lit(zse, "rand") &&
	     zcbor_bstr_encode_ptr(zse, sensor_random, sizeof(sensor_random));
	if (!ok) {
		LOG_ERR("smp_cmd_auth_resume: Failed to encode response");
		goto fail;
	}

	/* Add our response to the hash operation */
	ret = psa_hash_update(&hash_op, ctxt->cnbe->nb->data + 8,
			      (zse->payload_mut - ctxt->cnbe->nb->data - 8));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_resume: Failed to add our payload to the hash: %d", ret);
		goto fail;
	}
	ret = psa_hash_finish(&hash_op, auth_handshake_hash, sizeof(auth_handshake_hash),
			      &output_len);
	if (ret != PSA_SUCCESS || output_len != sizeof(auth_handshake_hash)) {
		LOG_ERR("smp_cmd_auth_resume: Failed to compute hash: %d", ret);
		goto fail;
	}

	return 0;

fail:
	/* Reset any authentication state back to defaults */
	auth_data_reset();

	/* Clean up any memory that we used */
	psa_hash_abort(&hash_op);
	psa_key_derivation_abort(&deriv_op);

	return MGMT_ERR_EUNKNOWN;
}

static int smp_cmd_auth_verify(struct mgmt_ctxt *ctxt)
{
	bool ok;
	int ret;
	zcbor_state_t *zse = ctxt->cnbe->zs;
	zcbor_state_t *zsd = ctxt->cnbd->zs;
	struct zcbor_string gateway_verify = { 0 };
	uint64_t session_id = 0;
	size_t output_len = 0;
	psa_mac_operation_t mac_op = PSA_MAC_OPERATION_INIT;
	uint8_t output_bytes[LCZ_PKI_AUTH_SMP_VERIFY_LEN];

	struct zcbor_map_decode_key_val auth_verify_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(id, zcbor_uint64_decode, &session_id),
		ZCBOR_MAP_DECODE_KEY_VAL(v, zcbor_bstr_decode, &gateway_verify),
	};

	/* Parse the input */
	ok = zcbor_map_decode_bulk(zsd, auth_verify_decode, ARRAY_SIZE(auth_verify_decode),
				   &output_len) == 0;
	if (!ok || session_id == 0 || gateway_verify.len != LCZ_PKI_AUTH_SMP_VERIFY_LEN) {
		LOG_ERR("smp_cmd_auth_verify: Failed to parse input message");
		goto fail;
	}

	/* Make sure that session ID matches the session that we have */
	if (session_id != auth_session_id) {
		LOG_ERR("smp_cmd_auth_verify: Invalid session id");
		goto fail;
	}

	/* Compute the expected gateway response */

	ret = psa_mac_verify_setup(&mac_op, auth_session_sig_key,
				   PSA_ALG_FULL_LENGTH_MAC(PSA_ALG_CMAC));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_verify: Gateway verify setup failed: %d", ret);
		goto fail;
	}

	/* Input the label */
	ret = psa_mac_update(&mac_op, LCZ_PKI_AUTH_VERIFY_GATEWAY_LABEL,
			     strlen(LCZ_PKI_AUTH_VERIFY_GATEWAY_LABEL));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_verify: Could not add label to gateway verify: %d", ret);
		goto fail;
	}

	/* Input the hash */
	ret = psa_mac_update(&mac_op, auth_handshake_hash, sizeof(auth_handshake_hash));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_verify: Could not add hash to gateway verify: %d", ret);
		goto fail;
	}

	/* Get the output */
	ret = psa_mac_verify_finish(&mac_op, gateway_verify.value, gateway_verify.len);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_verify: Could not verify gateway response: %d", ret);
		goto fail;
	}

	/* Compute the sensor response */

	ret = psa_mac_sign_setup(&mac_op, auth_session_sig_key,
				 PSA_ALG_FULL_LENGTH_MAC(PSA_ALG_CMAC));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_verify: Sensor verify setup failed: %d", ret);
		goto fail;
	}

	/* Input the label */
	ret = psa_mac_update(&mac_op, LCZ_PKI_AUTH_VERIFY_SENSOR_LABEL,
			     strlen(LCZ_PKI_AUTH_VERIFY_SENSOR_LABEL));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_verify: Could not add label to sensor verify: %d", ret);
		goto fail;
	}

	/* Input the hash */
	ret = psa_mac_update(&mac_op, auth_handshake_hash, sizeof(auth_handshake_hash));
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_verify: Could not add hash to sensor verify: %d", ret);
		goto fail;
	}

	/* Get the output */
	ret = psa_mac_sign_finish(&mac_op, output_bytes, sizeof(output_bytes), &output_len);
	if (ret != PSA_SUCCESS) {
		LOG_ERR("smp_cmd_auth_verify: Could not fetch sensor verify: %d", ret);
		goto fail;
	}

	/* Build our response */
	ok = zcbor_tstr_put_lit(zse, "id") && zcbor_uint64_put(zse, auth_session_id) &&
	     zcbor_tstr_put_lit(zse, "v") &&
	     zcbor_bstr_encode_ptr(zse, output_bytes, sizeof(output_bytes));
	if (!ok) {
		LOG_ERR("smp_cmd_auth_verify: Failed to encode response");
		goto fail;
	}

	/* For now, we can assume that we are authenticated */
	auth_status = LCZ_PKI_AUTH_SMP_STATUS_GOOD;
	/* Don't call the callbacks until we get the Status message from the gateway */

	return 0;

fail:
	/* Reset any authentication state back to defaults */
	auth_data_reset();

	/* Clean up any memory that we used */
	psa_mac_abort(&mac_op);

	return MGMT_ERR_EUNKNOWN;
}

static int smp_cmd_auth_status(struct mgmt_ctxt *ctxt)
{
	bool ok;
	zcbor_state_t *zse = ctxt->cnbe->zs;
	zcbor_state_t *zsd = ctxt->cnbd->zs;
	uint64_t session_id = 0;
	uint32_t auth_status = 0;
	size_t decoded = 0;

	struct zcbor_map_decode_key_val auth_status_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(id, zcbor_uint64_decode, &session_id),
		ZCBOR_MAP_DECODE_KEY_VAL(status, zcbor_uint32_decode, &auth_status),
	};

	/* Parse the input */
	ok = zcbor_map_decode_bulk(zsd, auth_status_decode, ARRAY_SIZE(auth_status_decode),
				   &decoded) == 0;
	if (!ok || session_id == 0) {
		LOG_ERR("smp_cmd_auth_status: Failed to parse input message");
		goto fail;
	}

	/* Verify the input parameters */
	if (session_id != auth_session_id || auth_status != LCZ_PKI_AUTH_SMP_STATUS_GOOD) {
		LOG_ERR("smp_cmd_auth_status: Status failed");
		goto fail;
	}

	/* Build our response */
	ok = zcbor_tstr_put_lit(zse, "id") && zcbor_uint64_put(zse, auth_session_id) &&
	     zcbor_tstr_put_lit(zse, "status") && zcbor_uint32_put(zse, auth_status);
	if (!ok) {
		LOG_ERR("smp_cmd_auth_status: Failed to encode response");
		goto fail;
	}

	/* Call callbacks for authentication success */
	auth_status_callback();

	return 0;

fail:
	auth_data_reset();
	return MGMT_ERR_EUNKNOWN;
}

/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
SYS_INIT(lcz_pki_auth_smp_periph_init, APPLICATION, CONFIG_LCZ_PKI_AUTH_SMP_INIT_PRIORITY);
static int lcz_pki_auth_smp_periph_init(const struct device *dev)
{
	/* Registered our group with the SMP server */
	mgmt_register_group(&lcz_pki_mgmt_group);
	return 0;
}
