/**
 * @file lcz_pki_auth_smp.h
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#ifndef __LCZ_PKI_AUTH_SMP_H__
#define __LCZ_PKI_AUTH_SMP_H__

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <zephyr.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/services/dfu_smp.h>
#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Global Constants, Macros and Type Definitions                                                  */
/**************************************************************************************************/
/* PKI Authentication SMP group command identifiers */
#define LCZ_PKI_AUTH_MGMT_ID_AUTH_START 1
#define LCZ_PKI_AUTH_MGMT_ID_AUTH_RESUME 2
#define LCZ_PKI_AUTH_MGMT_ID_AUTH_VERIFY 3
#define LCZ_PKI_AUTH_MGMT_ID_AUTH_STATUS 4

#define LCZ_PKI_AUTH_MGMT_SESSION_ID id
#define LCZ_PKI_AUTH_MGMT_SESSION_ID_STR STRINGIFY(LCZ_PKI_AUTH_MGMT_SESSION_ID)
#define LCZ_PKI_AUTH_MGMT_CERTIFICATE cert
#define LCZ_PKI_AUTH_MGMT_CERTIFICATE_STR STRINGIFY(LCZ_PKI_AUTH_MGMT_CERTIFICATE)
#define LCZ_PKI_AUTH_MGMT_RANDOM rand
#define LCZ_PKI_AUTH_MGMT_RANDOM_STR STRINGIFY(LCZ_PKI_AUTH_MGMT_RANDOM)
#define LCZ_PKI_AUTH_MGMT_VERIFY v
#define LCZ_PKI_AUTH_MGMT_VERIFY_STR STRINGIFY(LCZ_PKI_AUTH_MGMT_VERIFY)
#define LCZ_PKI_AUTH_MGMT_STATUS status
#define LCZ_PKI_AUTH_MGMT_STATUS_STR STRINGIFY(LCZ_PKI_AUTH_MGMT_STATUS)

#define LCZ_PKI_AUTH_RAND_LEN 16
#define LCZ_PKI_AUTH_SMP_SESSION_KEY_LEN 16 /* aes128 */
#define LCZ_PKI_AUTH_SMP_HANDSHAKE_HASH_LEN 32 /* sha256 */
#define LCZ_PKI_AUTH_SMP_VERIFY_LEN 16
#define LCZ_PKI_AUTH_SMP_SESSION_ENC_KEY_ALG PSA_ALG_CBC_NO_PADDING
#define LCZ_PKI_AUTH_SMP_SESSION_SIG_KEY_ALG PSA_ALG_CMAC
#define LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE PSA_KEY_TYPE_AES

#define LCZ_PKI_AUTH_KEY_DERIV_LABEL "key expansion"
#define LCZ_PKI_AUTH_VERIFY_GATEWAY_LABEL "gateway finished"
#define LCZ_PKI_AUTH_VERIFY_SENSOR_LABEL "sensor finished"

#define LCZ_PKI_AUTH_SMP_STATUS_GOOD 1

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_PERIPHERAL)
/**
 * @brief Function pointer for receiving peripheral "Authentication Complete" event callbacks
 *
 * @param[in] status Status of the authentication (true = success)
 */
typedef void (*lcz_pki_auth_smp_periph_auth_complete_t)(bool status);

struct lcz_pki_auth_smp_periph_auth_callback_agent {
	sys_snode_t node;
	lcz_pki_auth_smp_periph_auth_complete_t cb;
};
#endif

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
/**
 * @brief Function pointer for receiving central "Authentication Complete" event callbacks
 *
 * @param[in] status Status of the authentication (true = success)
 */
typedef void (*lcz_pki_auth_smp_central_auth_complete_t)(const bt_addr_le_t *addr, bool status);

struct lcz_pki_auth_smp_central_auth_callback_agent {
	sys_snode_t node;
	lcz_pki_auth_smp_central_auth_complete_t cb;
};
#endif

/**************************************************************************************************/
/* Global Function Prototypes                                                                     */
/**************************************************************************************************/
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
/**
 * @brief Register a handler to receive central "Authentication Complete" events
 *
 * @param[in] cb Callback function to register
 */
void lcz_pki_auth_smp_central_register_handler(
	struct lcz_pki_auth_smp_central_auth_callback_agent *cb);

/**
 * @brief Remove a handler from the central "Authenication Complete" event callback list
 *
 * @param[in] cb Callback function to de-register
 */
void lcz_pki_auth_smp_central_unregister_handler(
	struct lcz_pki_auth_smp_central_auth_callback_agent *cb);

/**
 * @brief Retrieve the negotiated session keys for a peripheral
 *
 * @param[in] addr BLE address of the device for which the key should be returned
 * @param[out] enc_key Pointer to where encryption key should be returned
 * @param[out] sig_key Pointer to where signing key should be returned
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_smp_central_get_keys(const bt_addr_le_t *addr, psa_key_id_t *enc_key,
				      psa_key_id_t *sig_key);

/**
 * @brief Start the SMP authentication process with a BLE peripheral
 *
 * @param[in] smp_client A pointer to the SMP client in use for the connection
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_smp_central_start_auth(struct bt_dfu_smp *smp_client);
#endif /* LCZ_PKI_AUTH_SMP_CENTRAL */

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_PERIPHERAL)
/**
 * @brief Register a handler to receive peripheral "Authentication Complete" events
 *
 * @param[in] cb Callback function to register
 */
void lcz_pki_auth_smp_periph_register_handler(
	struct lcz_pki_auth_smp_periph_auth_callback_agent *cb);

/**
 * @brief Remove a handler from the peripheral "Authenication Complete" event callback list
 *
 * @param[in] cb Callback function to de-register
 */
void lcz_pki_auth_smp_periph_unregister_handler(
	struct lcz_pki_auth_smp_periph_auth_callback_agent *cb);

/**
 * @brief Retrieve the negotiated session keys as a peripheral
 *
 * @param[out] enc_key Pointer to where encryption key should be returned
 * @param[out] sig_key Pointer to where signing key should be returned
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_smp_periph_get_keys(psa_key_id_t *enc_key, psa_key_id_t *sig_key);
#endif /* LCZ_PKI_AUTH_SMP_PERIPHERAL */

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_PKI_AUTH_SMP_H__ */
