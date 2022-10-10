/**
 * @file lcz_pki_auth.h
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#ifndef __LCZ_PKI_AUTH_H__
#define __LCZ_PKI_AUTH_H__

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <zephyr.h>
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Global Constants, Macros and Type Definitions                                                  */
/**************************************************************************************************/
typedef enum {
	LCZ_PKI_AUTH_STORE_DEVICE_MANAGEMENT,
	LCZ_PKI_AUTH_STORE_TELEMETRY,
	LCZ_PKI_AUTH_STORE_PEER_TO_PEER,
	LCZ_PKI_AUTH_STORE_FILE_SERVICE,

	LCZ_PKI_AUTH_STORE__NUM,
} LCZ_PKI_AUTH_STORE_T;

typedef enum {
	LCZ_PKI_AUTH_FILE_PRIVATE_KEY,
	LCZ_PKI_AUTH_FILE_PUBLIC_KEY,
	LCZ_PKI_AUTH_FILE_CSR,
	LCZ_PKI_AUTH_FILE_DEVICE_CERTIFICATE,
	LCZ_PKI_AUTH_FILE_CA_CERTIFICATE,

	LCZ_PKI_AUTH_FILE__NUM,
} LCZ_PKI_AUTH_FILE_T;

#define LCZ_PKI_AUTH_STATUS_PRIV_KEY_EXISTS 0x01
#define LCZ_PKI_AUTH_STATUS_PUB_KEY_EXISTS 0x02
#define LCZ_PKI_AUTH_STATUS_CSR_EXISTS 0x04
#define LCZ_PKI_AUTH_STATUS_DEV_CERT_EXISTS 0x08
#define LCZ_PKI_AUTH_STATUS_CA_CERT_EXISTS 0x10
#define LCZ_PKI_AUTH_STATUS_CA_CERT_VALID 0x20
#define LCZ_PKI_AUTH_STATUS_DEV_CERT_VALID 0x40
#define LCZ_PKI_AUTH_STATUS_DEV_CERT_MATCHES 0x80
#define LCZ_PKI_AUTH_STATUS_GOOD 0xFF

/**************************************************************************************************/
/* Global Function Prototypes                                                                     */
/**************************************************************************************************/
/**
 * @brief Generate the complete filename of a authentication file from a given store
 *
 * @param[in] store Authentication store
 * @param[in] file File to obtain
 * @param[out] filename Pointer to the location where the filename will be written
 * @param[in] filename_size Size of the memory pointed to by filename
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_file_name_get(LCZ_PKI_AUTH_STORE_T store, LCZ_PKI_AUTH_FILE_T file, char *filename,
			       size_t filename_size);

/**
 * @brief Generate a new key pair for a authentication store
 *
 * @param[in] store Store for which to generate a new key pair
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_key_pair_gen(LCZ_PKI_AUTH_STORE_T store);

/**
 * @brief Generate a certificate signing request (CSR) for an authentication store
 *
 * @param[in] store Store for which to generate a new CSR
 * @param[in] country Pointer to string holding the country designation for the CSR
 * @param[in] organization Pointer to string holding the organization designation for the CSR
 * @param[in] organization_unit Pointer to string holding the organizational unit designation for the CSR
 * @param[in] common_name Pointer to string holding the common name for the CSR
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_csr_gen(LCZ_PKI_AUTH_STORE_T store, const char *country, const char *organization,
			 const char *organization_unit, const char *common_name);

#if defined(CONFIG_TLS_CREDENTIALS)
/**
 * @brief Load the specified credential into the TLS database
 *
 * @param[in] store Store to load
 * @param[in] tls_tag TLS tag to use for the credential
 * @param[in] root_only Only load root certificate
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_tls_credential_load(LCZ_PKI_AUTH_STORE_T store, int tls_tag, bool root_only);

/**
 * @brief Unload the specified credential from the TLS database
 *
 * @param[in] store Store to unload
 * @param[in] tls_tag TLS tag used for the credential
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_tls_credential_unload(LCZ_PKI_AUTH_STORE_T store, int tls_tag);
#endif

/**
 * @brief Return the status of the specified credential store
 *
 * @param[in] store Store for which to determine status
 *
 * @returns A bitmask of LCZ_PKI_AUTH_STORE_STATUS_* flags representing
 * the state of the credential store
 */
uint8_t lcz_pki_auth_store_status(LCZ_PKI_AUTH_STORE_T store);

/**
 * @brief Load and parse the CA certificate for the specified credential store
 *
 * @param[in] store Store for which to read the CA certificate
 * @param[in] cert Pointer to mbedtls certificate structure to hold certificate
 *
 * @note The cert pointer must point to an already-initialized mbedtls certificate
 * structure. The caller is responsible for freeing the certificate.
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_get_ca(LCZ_PKI_AUTH_STORE_T store, mbedtls_x509_crt *cert);

/**
 * @brief Load and parse the device certificate for the specified credential store
 *
 * @param[in] store Store for which to read the device certificate
 * @param[in] cert Pointer to mbedtls certificate structure to hold certificate
 *
 * @note The cert pointer must point to an already-initialized mbedtls certificate
 * structure. The caller is responsible for freeing the certificate.
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_get_dev_cert(LCZ_PKI_AUTH_STORE_T store, mbedtls_x509_crt *cert);

/**
 * @brief Load and parse the private key for the specified credential store
 *
 * @param[in] store Store for which to read the private key
 * @param[in] key Pointer to mbedtls key structure to hold the private key
 *
 * @note The key pointer must point to an already-initialized mbedtls key
 * structure. The caller is responsible for freeing the key.
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_get_priv_key(LCZ_PKI_AUTH_STORE_T store, mbedtls_pk_context *key);

/**
 * @brief Convert an mbedtls private key into a PSA key
 *
 * @param[in] pk mbedtls key context to convert
 * @param[out] key New PSA key id
 *
 * @returns 0 on success, <0 on error
 */
int lcz_pki_auth_pk_to_psa_key(mbedtls_pk_context *pk, psa_key_id_t *key);

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_PKI_AUTH_H__ */
