/**
 * @file lcz_lwm2m_transport_ble_peripheral.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_pki_auth, CONFIG_LCZ_PKI_AUTH_LOG_LEVEL);
#include <zephyr.h>
#include <string.h>
#include <stdio.h>
#include <fs/fs.h>
#if defined(CONFIG_TLS_CREDENTIALS)
#include <net/tls_credentials.h>
#endif

#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "psa/crypto.h"
#include "psa/error.h"

#include "attr.h"
#include "file_system_utilities.h"
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
#include "encrypted_file_storage.h"
#endif

#include "lcz_pki_auth.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
static const struct {
	int trust_path;
	int key_path;
} STORE_ATTRIBUTES[LCZ_PKI_AUTH_STORE__NUM] = {
	{ ATTR_ID_dm_trust_path, ATTR_ID_dm_key_path },
	{ ATTR_ID_tel_trust_path, ATTR_ID_tel_key_path },
	{ ATTR_ID_p2p_trust_path, ATTR_ID_p2p_key_path },
	{ ATTR_ID_fs_trust_path, ATTR_ID_fs_key_path },
};

static const struct {
	char *file;
	bool key; /* true if key store, false if trust store */
} STORE_FILES[LCZ_PKI_AUTH_FILE__NUM] = {
	{ "private.key", true }, { "public.key", true }, { "cert.csr", false },
	{ "cert.crt", false },	 { "ca.crt", false },
};

/* Size of the largest EC private or public key we will generate */
#define KEY_BUFFER_SIZE 256

/* Size of the largest CSR we will generate */
#define CSR_BUFFER_SIZE 1024

/* Size of the largest certificate we can support */
#define CERT_BUFFER_SIZE 4096

/* Maximum size of the Subject string in the CSR */
#define SUBJECT_BUFFER_SIZE 128

typedef struct {
	uint8_t *private_key;
	int private_key_size;
	uint8_t *device_cert;
	int device_cert_size;
	uint8_t *ca_cert;
	int ca_cert_size;
} LCZ_PKI_AUTH_STORE_CACHE_T;

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int rng(void *context, unsigned char *data, size_t size);
static bool file_exists(LCZ_PKI_AUTH_STORE_T store, LCZ_PKI_AUTH_FILE_T file);
#if defined(CONFIG_TLS_CREDENTIALS)
static int file_size(LCZ_PKI_AUTH_STORE_T store, LCZ_PKI_AUTH_FILE_T file);
#endif
static int load_file(LCZ_PKI_AUTH_STORE_T store, LCZ_PKI_AUTH_FILE_T file, uint8_t *buffer,
		     size_t buffer_size);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
#if defined(CONFIG_TLS_CREDENTIALS)
static LCZ_PKI_AUTH_STORE_CACHE_T store_cache[LCZ_PKI_AUTH_STORE__NUM];
#endif

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
int lcz_pki_auth_file_name_get(LCZ_PKI_AUTH_STORE_T store, LCZ_PKI_AUTH_FILE_T file, char *filename,
			       size_t filename_size)
{
	int len;

	if (store >= LCZ_PKI_AUTH_STORE__NUM || file >= LCZ_PKI_AUTH_FILE__NUM ||
	    filename == NULL) {
		return -EINVAL;
	}

	if (STORE_FILES[file].key) {
		len = snprintf(filename, 0, "%s/%s",
			       (char *)attr_get_quasi_static(STORE_ATTRIBUTES[store].key_path),
			       STORE_FILES[file].file);
		if (len < filename_size) {
			len = snprintf(
				filename, filename_size, "%s/%s",
				(char *)attr_get_quasi_static(STORE_ATTRIBUTES[store].key_path),
				STORE_FILES[file].file);
		} else {
			return -ENOMEM;
		}
	} else {
		len = snprintf(filename, 0, "%s/%s",
			       (char *)attr_get_quasi_static(STORE_ATTRIBUTES[store].trust_path),
			       STORE_FILES[file].file);
		if (len < filename_size) {
			len = snprintf(
				filename, filename_size, "%s/%s",
				(char *)attr_get_quasi_static(STORE_ATTRIBUTES[store].trust_path),
				STORE_FILES[file].file);
		} else {
			return -ENOMEM;
		}
	}

	return 0;
}

int lcz_pki_auth_key_pair_gen(LCZ_PKI_AUTH_STORE_T store)
{
	uint8_t filename[FSU_MAX_ABS_PATH_SIZE];
	uint8_t *key_buffer;
	mbedtls_pk_context key;
	int ret = 0;

	/* Allocate space to hold our key */
	key_buffer = k_malloc(KEY_BUFFER_SIZE);
	if (key_buffer == NULL) {
		return -ENOMEM;
	}

	/* Create the directories for this authentication store */
	fsu_mkdir_abs((char *)attr_get_quasi_static(STORE_ATTRIBUTES[store].key_path), true);
	fsu_mkdir_abs((char *)attr_get_quasi_static(STORE_ATTRIBUTES[store].trust_path), true);

	/* Make sure that the key and trust stores are empty */
	if (lcz_pki_auth_file_name_get(store, LCZ_PKI_AUTH_FILE_PRIVATE_KEY, filename,
				       sizeof(filename)) == 0) {
		fs_unlink(filename);
	}
	if (lcz_pki_auth_file_name_get(store, LCZ_PKI_AUTH_FILE_PUBLIC_KEY, filename,
				       sizeof(filename)) == 0) {
		fs_unlink(filename);
	}
	if (lcz_pki_auth_file_name_get(store, LCZ_PKI_AUTH_FILE_CSR, filename, sizeof(filename)) ==
	    0) {
		fs_unlink(filename);
	}
	if (lcz_pki_auth_file_name_get(store, LCZ_PKI_AUTH_FILE_DEVICE_CERTIFICATE, filename,
				       sizeof(filename)) == 0) {
		fs_unlink(filename);
	}
	if (lcz_pki_auth_file_name_get(store, LCZ_PKI_AUTH_FILE_CA_CERTIFICATE, filename,
				       sizeof(filename)) == 0) {
		fs_unlink(filename);
	}

	/* Initialize our key structure */
	mbedtls_pk_init(&key);

	ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	if (ret != 0) {
		LOG_ERR("lcz_pki_auth_key_pair_gen: mbedls_pk_setup failed: %d", ret);
	}

	if (ret == 0) {
		ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), rng, NULL);
		if (ret != 0) {
			LOG_ERR("lcz_pki_auth_key_pair_gen: mbedtls_ecp_gen_key failed: %d", ret);
		}
	}

	if (ret == 0) {
		ret = mbedtls_pk_write_key_pem(&key, key_buffer, KEY_BUFFER_SIZE);
		if (ret != 0) {
			LOG_ERR("lcz_pki_auth_key_pair_gen: mbedtls_pk_write_key_pem failed: %d",
				ret);
		} else {
			if (lcz_pki_auth_file_name_get(store, LCZ_PKI_AUTH_FILE_PRIVATE_KEY,
						       filename, sizeof(filename)) == 0) {
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
				if (efs_is_encrypted_path(filename)) {
					ret = efs_write(filename, key_buffer, strlen(key_buffer));
				} else
#endif
				{
					ret = fsu_write_abs(filename, key_buffer,
							    strlen(key_buffer));
				}
				if (ret < 0) {
					LOG_ERR("lcz_pki_auth_key_pair_gen: file write failed: %d",
						ret);
				} else {
					/* Write was successful */
					ret = 0;
				}
			} else {
				ret = -EINVAL;
			}
		}
	}

	if (ret == 0) {
		ret = mbedtls_pk_write_pubkey_pem(&key, key_buffer, KEY_BUFFER_SIZE);
		if (ret != 0) {
			LOG_ERR("lcz_pki_auth_key_pair_gen: mbedtls_pk_write_pubkey_pem failed: %d",
				ret);
		} else {
			if (lcz_pki_auth_file_name_get(store, LCZ_PKI_AUTH_FILE_PUBLIC_KEY,
						       filename, sizeof(filename)) == 0) {
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
				if (efs_is_encrypted_path(filename)) {
					ret = efs_write(filename, key_buffer, strlen(key_buffer));
				} else
#endif
				{
					ret = fsu_write_abs(filename, key_buffer,
							    strlen(key_buffer));
				}
				if (ret < 0) {
					LOG_ERR("lcz_pki_auth_key_pair_gen: file write failed: %d",
						ret);
				} else {
					/* Write was successful */
					ret = 0;
				}
			} else {
				ret = -EINVAL;
			}
		}
	}

	/* Clear the memory that held the key buffer */
	memset(key_buffer, 0, KEY_BUFFER_SIZE);
	k_free(key_buffer);

	/* Free any memory associated with our key */
	mbedtls_pk_free(&key);

	return ret;
}

int lcz_pki_auth_csr_gen(LCZ_PKI_AUTH_STORE_T store, const char *country, const char *organization,
			 const char *organization_unit, const char *common_name)
{
	uint8_t filename[FSU_MAX_ABS_PATH_SIZE];
	mbedtls_pk_context key;
	mbedtls_x509write_csr req;
	char *output_buf = NULL;
	char *subject = NULL;
	int ret = 0;

	/* Allocate space to hold our CSR */
	output_buf = k_malloc(CSR_BUFFER_SIZE);
	if (output_buf == NULL) {
		return -ENOMEM;
	}

	/* Allocate memory to hold the subject string */
	subject = k_malloc(SUBJECT_BUFFER_SIZE);
	if (subject == NULL) {
		k_free(output_buf);
		return -ENOMEM;
	}

	/* Build the subject string */
	ret = snprintf(subject, SUBJECT_BUFFER_SIZE, "C=%s,O=%s,OU=%s,CN=%s", country, organization,
		       organization_unit, common_name);
	if (ret > SUBJECT_BUFFER_SIZE) {
		LOG_ERR("lcz_pki_auth_csr_gen: Subject longer than buffer: %d > %d", ret,
			SUBJECT_BUFFER_SIZE);
		ret = -ENOMEM;
		goto done;
	}

	/* Initialize some mbedtls data structures */
	mbedtls_x509write_csr_init(&req);
	mbedtls_pk_init(&key);

	/* Read our private key file */
	ret = load_file(store, LCZ_PKI_AUTH_FILE_PRIVATE_KEY, output_buf, CSR_BUFFER_SIZE);
	if (ret < 0) {
		LOG_ERR("lcz_pki_auth_csr_gen: Could not read privatekey file: %d", ret);
		goto done;
	}
	ret = mbedtls_pk_parse_key(&key, output_buf, strlen(output_buf) + 1, NULL, 0, rng, NULL);
	if (ret < 0) {
		LOG_ERR("lcz_pki_auth_csr_gen: Could not parse key: %d", ret);
		goto done;
	}

	/* Generate the CSR */
	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
	ret = mbedtls_x509write_csr_set_subject_name(&req, subject);
	if (ret != 0) {
		LOG_ERR("lcz_pki_auth_csr_gen: mbedtls_x509write_csr_set_subject_name failed: %d",
			ret);
		goto done;
	}
	mbedtls_x509write_csr_set_key(&req, &key);
	memset(output_buf, 0, CSR_BUFFER_SIZE);
	ret = mbedtls_x509write_csr_pem(&req, output_buf, CSR_BUFFER_SIZE, rng, NULL);
	if (ret != 0) {
		LOG_ERR("lcz_pki_auth_csr_gen: Failed to generate CSR: %d", ret);
		goto done;
	}

	/* Write the output to the file */
	if (lcz_pki_auth_file_name_get(store, LCZ_PKI_AUTH_FILE_CSR, filename, sizeof(filename)) ==
	    0) {
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
		if (efs_is_encrypted_path(filename)) {
			ret = efs_write(filename, output_buf, strlen(output_buf));
		} else
#endif
		{
			ret = fsu_write_abs(filename, output_buf, strlen(output_buf));
		}
		if (ret < 0) {
			LOG_ERR("lcz_pki_auth_csr_gen: file write failed: %d", ret);
		} else {
			/* Write was successful */
			ret = 0;
		}
	} else {
		ret = -EINVAL;
	}

done:
	if (output_buf != NULL) {
		memset(output_buf, 0, CSR_BUFFER_SIZE);
		k_free(output_buf);
	}
	if (subject != NULL) {
		k_free(subject);
	}
	mbedtls_x509write_csr_free(&req);
	mbedtls_pk_free(&key);

	return ret;
}

#if defined(CONFIG_TLS_CREDENTIALS)
int lcz_pki_auth_tls_credential_load(LCZ_PKI_AUTH_STORE_T store, int tls_tag)
{
	int ret = 0;

	/* "Unload" the old credential first */
	lcz_pki_auth_tls_credential_unload(store, tls_tag);

	/* Make sure that all of the files are present */
	if (file_exists(store, LCZ_PKI_AUTH_FILE_PRIVATE_KEY) == false) {
		return -ENOENT;
	}
	if (file_exists(store, LCZ_PKI_AUTH_FILE_DEVICE_CERTIFICATE) == false) {
		return -ENOENT;
	}
	if (file_exists(store, LCZ_PKI_AUTH_FILE_CA_CERTIFICATE) == false) {
		return -ENOENT;
	}

	/* Allocate memory for the new credential */
	if (store_cache[store].private_key == NULL) {
		store_cache[store].private_key_size =
			file_size(store, LCZ_PKI_AUTH_FILE_PRIVATE_KEY) + 1;
		store_cache[store].private_key = k_malloc(store_cache[store].private_key_size);
		if (store_cache[store].private_key == NULL) {
			LOG_ERR("lcz_pki_auth_tls_credential_add: No memory for private key");
			ret = -ENOMEM;
			goto fail;
		}
	}
	if (store_cache[store].device_cert == NULL) {
		store_cache[store].device_cert_size =
			file_size(store, LCZ_PKI_AUTH_FILE_DEVICE_CERTIFICATE) + 1;
		store_cache[store].device_cert = k_malloc(store_cache[store].device_cert_size);
		if (store_cache[store].device_cert == NULL) {
			LOG_ERR("lcz_pki_auth_tls_credential_add: No memory for device cert");
			ret = -ENOMEM;
			goto fail;
		}
	}
	if (store_cache[store].ca_cert == NULL) {
		store_cache[store].ca_cert_size =
			file_size(store, LCZ_PKI_AUTH_FILE_CA_CERTIFICATE) + 1;
		store_cache[store].ca_cert = k_malloc(store_cache[store].ca_cert_size);
		if (store_cache[store].ca_cert == NULL) {
			LOG_ERR("lcz_pki_auth_tls_credential_add: No memory for CA cert");
			ret = -ENOMEM;
			goto fail;
		}
	}

	/* Load the device certificate */
	ret = load_file(store, LCZ_PKI_AUTH_FILE_DEVICE_CERTIFICATE, store_cache[store].device_cert,
			store_cache[store].device_cert_size);
	if (ret < 0) {
		goto fail;
	}
	ret = tls_credential_add(tls_tag, TLS_CREDENTIAL_SERVER_CERTIFICATE,
				 store_cache[store].device_cert,
				 store_cache[store].device_cert_size);
	if (ret < 0) {
		LOG_ERR("lcz_pki_auth_tls_credential_load: Couldn't add device certificate: %d",
			ret);
		goto fail;
	}

	/* Load the CA certificate */
	ret = load_file(store, LCZ_PKI_AUTH_FILE_CA_CERTIFICATE, store_cache[store].ca_cert,
			store_cache[store].ca_cert_size);
	if (ret < 0) {
		goto fail;
	}
	ret = tls_credential_add(tls_tag, TLS_CREDENTIAL_CA_CERTIFICATE, store_cache[store].ca_cert,
				 store_cache[store].ca_cert_size);
	if (ret < 0) {
		LOG_ERR("lcz_pki_auth_tls_credential_load: Couldn't add CA certificate: %d", ret);
		goto fail;
	}

	/* Load the private key */
	ret = load_file(store, LCZ_PKI_AUTH_FILE_PRIVATE_KEY, store_cache[store].private_key,
			store_cache[store].private_key_size);
	if (ret < 0) {
		goto fail;
	}
	ret = tls_credential_add(tls_tag, TLS_CREDENTIAL_PRIVATE_KEY,
				 store_cache[store].private_key,
				 store_cache[store].private_key_size);
	if (ret < 0) {
		LOG_ERR("lcz_pki_auth_tls_credential_load: Couldn't add private key: %d", ret);
		goto fail;
	}

	return 0;

fail:
	/* Undo anything that we might have done */
	lcz_pki_auth_tls_credential_unload(store, tls_tag);

	return ret;
}

int lcz_pki_auth_tls_credential_unload(LCZ_PKI_AUTH_STORE_T store, int tls_tag)
{
	if (store_cache[store].private_key != NULL) {
		(void)tls_credential_delete(tls_tag, TLS_CREDENTIAL_PRIVATE_KEY);
		memset(store_cache[store].private_key, 0, store_cache[store].private_key_size);
		k_free(store_cache[store].private_key);
		store_cache[store].private_key = NULL;
		store_cache[store].private_key_size = 0;
	}
	if (store_cache[store].device_cert != NULL) {
		(void)tls_credential_delete(tls_tag, TLS_CREDENTIAL_SERVER_CERTIFICATE);
		memset(store_cache[store].device_cert, 0, store_cache[store].device_cert_size);
		k_free(store_cache[store].device_cert);
		store_cache[store].device_cert = NULL;
		store_cache[store].device_cert_size = 0;
	}
	if (store_cache[store].ca_cert != NULL) {
		(void)tls_credential_delete(tls_tag, TLS_CREDENTIAL_CA_CERTIFICATE);
		memset(store_cache[store].ca_cert, 0, store_cache[store].ca_cert_size);
		k_free(store_cache[store].ca_cert);
		store_cache[store].ca_cert = NULL;
		store_cache[store].ca_cert_size = 0;
	}

	return 0;
}
#endif /* CONFIG_TLS_CREDENTIALS */

uint8_t lcz_pki_auth_store_status(LCZ_PKI_AUTH_STORE_T store)
{
	uint8_t *priv_key_buffer = NULL;
	uint8_t *pub_key_buffer = NULL;
	uint8_t *ca_cert_buffer = NULL;
	uint8_t *dev_cert_buffer = NULL;
	mbedtls_pk_context priv_key;
	mbedtls_pk_context pub_key;
	mbedtls_x509_crt ca_cert;
	mbedtls_x509_crt dev_cert;
	int ret = 0;
	uint8_t flags = 0;

	/* Check to see what files are present */
	if (file_exists(store, LCZ_PKI_AUTH_FILE_PRIVATE_KEY)) {
		flags |= LCZ_PKI_AUTH_STATUS_PRIV_KEY_EXISTS;
	}
	if (file_exists(store, LCZ_PKI_AUTH_FILE_PUBLIC_KEY)) {
		flags |= LCZ_PKI_AUTH_STATUS_PUB_KEY_EXISTS;
	}
	if (file_exists(store, LCZ_PKI_AUTH_FILE_CSR)) {
		flags |= LCZ_PKI_AUTH_STATUS_CSR_EXISTS;
	}
	if (file_exists(store, LCZ_PKI_AUTH_FILE_DEVICE_CERTIFICATE)) {
		flags |= LCZ_PKI_AUTH_STATUS_DEV_CERT_EXISTS;
	}
	if (file_exists(store, LCZ_PKI_AUTH_FILE_CA_CERTIFICATE)) {
		flags |= LCZ_PKI_AUTH_STATUS_CA_CERT_EXISTS;
	}

	/* Allocate some memory to read the files */
	mbedtls_pk_init(&pub_key);
	mbedtls_pk_init(&priv_key);
	mbedtls_x509_crt_init(&ca_cert);
	mbedtls_x509_crt_init(&dev_cert);
	priv_key_buffer = k_malloc(KEY_BUFFER_SIZE);
	if (priv_key_buffer == NULL) {
		goto done;
	}
	pub_key_buffer = k_malloc(KEY_BUFFER_SIZE);
	if (pub_key_buffer == NULL) {
		goto done;
	}
	ca_cert_buffer = k_malloc(CERT_BUFFER_SIZE);
	if (ca_cert_buffer == NULL) {
		goto done;
	}
	dev_cert_buffer = k_malloc(CERT_BUFFER_SIZE);
	if (dev_cert_buffer == NULL) {
		goto done;
	}

	/* Read the private key */
	if ((flags & LCZ_PKI_AUTH_STATUS_PRIV_KEY_EXISTS) != 0) {
		ret = load_file(store, LCZ_PKI_AUTH_FILE_PRIVATE_KEY, priv_key_buffer,
				KEY_BUFFER_SIZE);
		if (ret < 0) {
			LOG_ERR("lcz_pki_auth_store_status: Could not load private key: %d", ret);
			flags &= ~LCZ_PKI_AUTH_STATUS_PRIV_KEY_EXISTS;
			goto done;
		}
		ret = mbedtls_pk_parse_key(&priv_key, priv_key_buffer, strlen(priv_key_buffer) + 1,
					   NULL, 0, rng, NULL);
		if (ret < 0) {
			LOG_ERR("lcz_pki_auth_store_status: Could not parse private key: %d", ret);
			flags &= ~LCZ_PKI_AUTH_STATUS_PRIV_KEY_EXISTS;
			goto done;
		}
	}

	/* Read the public key */
	if ((flags & LCZ_PKI_AUTH_STATUS_PUB_KEY_EXISTS) != 0) {
		ret = load_file(store, LCZ_PKI_AUTH_FILE_PUBLIC_KEY, pub_key_buffer,
				KEY_BUFFER_SIZE);
		if (ret < 0) {
			LOG_ERR("lcz_pki_auth_store_status: Could not load public key: %d", ret);
			flags &= ~LCZ_PKI_AUTH_STATUS_PUB_KEY_EXISTS;
			goto done;
		}
		ret = mbedtls_pk_parse_public_key(&pub_key, pub_key_buffer,
						  strlen(pub_key_buffer) + 1);
		if (ret < 0) {
			LOG_ERR("lcz_pki_auth_store_status: Could not parse public key: %d", ret);
			flags &= ~LCZ_PKI_AUTH_STATUS_PUB_KEY_EXISTS;
			goto done;
		}
	}

	/* Verify that the public key is derived from the private key */
	if ((flags & (LCZ_PKI_AUTH_STATUS_PRIV_KEY_EXISTS | LCZ_PKI_AUTH_STATUS_PUB_KEY_EXISTS)) ==
	    (LCZ_PKI_AUTH_STATUS_PRIV_KEY_EXISTS | LCZ_PKI_AUTH_STATUS_PUB_KEY_EXISTS)) {
		ret = mbedtls_pk_check_pair(&pub_key, &priv_key, rng, NULL);
		if (ret < 0) {
			LOG_ERR("lcz_pki_auth_store_status: Public and private key do not match: %d",
				ret);
			flags &= ~LCZ_PKI_AUTH_STATUS_PUB_KEY_EXISTS;
			flags &= ~LCZ_PKI_AUTH_STATUS_PRIV_KEY_EXISTS;
			goto done;
		}
	}

	/* Read the CA certificate */
	if ((flags & LCZ_PKI_AUTH_STATUS_CA_CERT_EXISTS) != 0) {
		ret = load_file(store, LCZ_PKI_AUTH_FILE_CA_CERTIFICATE, ca_cert_buffer,
				CERT_BUFFER_SIZE);
		if (ret < 0) {
			LOG_ERR("lcz_pki_auth_store_status: Could not load CA certificate: %d",
				ret);
			flags &= ~LCZ_PKI_AUTH_STATUS_CA_CERT_EXISTS;
			goto done;
		}
	}

	/* Parse the CA certificate */
	if ((flags & LCZ_PKI_AUTH_STATUS_CA_CERT_EXISTS) != 0) {
		ret = mbedtls_x509_crt_parse(&ca_cert, ca_cert_buffer, strlen(ca_cert_buffer) + 1);
		if (ret < 0) {
			LOG_ERR("lcz_pki_auth_store_status: Could not parse CA certificate: %d",
				ret);
			flags &= ~LCZ_PKI_AUTH_STATUS_CA_CERT_EXISTS;
			goto done;
		}
		flags |= LCZ_PKI_AUTH_STATUS_CA_CERT_VALID;
	}

	/* Read the device certificate */
	if ((flags & LCZ_PKI_AUTH_STATUS_DEV_CERT_EXISTS) != 0) {
		ret = load_file(store, LCZ_PKI_AUTH_FILE_DEVICE_CERTIFICATE, dev_cert_buffer,
				CERT_BUFFER_SIZE);
		if (ret < 0) {
			LOG_ERR("lcz_pki_auth_store_status: Could not load device certificate: %d",
				ret);
			flags &= ~LCZ_PKI_AUTH_STATUS_DEV_CERT_EXISTS;
			goto done;
		}
	}

	/* Parse the device certificate */
	if ((flags & LCZ_PKI_AUTH_STATUS_DEV_CERT_EXISTS) != 0) {
		ret = mbedtls_x509_crt_parse(&dev_cert, dev_cert_buffer,
					     strlen(dev_cert_buffer) + 1);
		if (ret < 0) {
			LOG_ERR("lcz_pki_auth_store_status: Could not parse device certificate: %d",
				ret);
			flags &= ~LCZ_PKI_AUTH_STATUS_DEV_CERT_EXISTS;
			goto done;
		}
		flags |= LCZ_PKI_AUTH_STATUS_DEV_CERT_VALID;
	}

	/* Make sure the the public key in the device certificate matches the public key file */
	if ((flags & LCZ_PKI_AUTH_STATUS_DEV_CERT_VALID) != 0) {
		ret = mbedtls_pk_check_pair(&(dev_cert.pk), &priv_key, rng, NULL);
		if (ret < 0) {
			LOG_ERR("lcz_pki_auth_store_status: Device certificate key doesn't match: %d",
				ret);
			goto done;
		}
		flags |= LCZ_PKI_AUTH_STATUS_DEV_CERT_MATCHES;
	}

done:
	mbedtls_pk_free(&pub_key);
	mbedtls_pk_free(&priv_key);
	mbedtls_x509_crt_free(&ca_cert);
	mbedtls_x509_crt_free(&dev_cert);
	if (priv_key_buffer != NULL) {
		memset(priv_key_buffer, 0, KEY_BUFFER_SIZE);
		k_free(priv_key_buffer);
	}
	if (pub_key_buffer != NULL) {
		memset(pub_key_buffer, 0, KEY_BUFFER_SIZE);
		k_free(pub_key_buffer);
	}
	if (ca_cert_buffer != NULL) {
		memset(ca_cert_buffer, 0, CERT_BUFFER_SIZE);
		k_free(ca_cert_buffer);
	}
	if (dev_cert_buffer != NULL) {
		memset(dev_cert_buffer, 0, CERT_BUFFER_SIZE);
		k_free(dev_cert_buffer);
	}

	return flags;
}

int lcz_pki_auth_get_ca(LCZ_PKI_AUTH_STORE_T store, mbedtls_x509_crt *cert)
{
	uint8_t *ca_cert_buffer = NULL;
	int ret = 0;

	/* Allocate memory to read the CA certificate file */
	ca_cert_buffer = k_malloc(CERT_BUFFER_SIZE);
	if (ca_cert_buffer == NULL) {
		ret = -ENOMEM;
		goto done;
	}

	/* Load the CA certificate file */
	ret = load_file(store, LCZ_PKI_AUTH_FILE_CA_CERTIFICATE, ca_cert_buffer, CERT_BUFFER_SIZE);
	if (ret < 0) {
		goto done;
	}

	/* Parse the certificate */
	ret = mbedtls_x509_crt_parse(cert, ca_cert_buffer, strlen(ca_cert_buffer) + 1);
	if (ret < 0) {
		LOG_ERR("lcz_pki_auth_get_ca: Could not parse CA certificate: %d", ret);
		goto done;
	}

done:
	if (ca_cert_buffer != NULL) {
		memset(ca_cert_buffer, 0, CERT_BUFFER_SIZE);
		k_free(ca_cert_buffer);
	}

	return ret;
}

int lcz_pki_auth_get_dev_cert(LCZ_PKI_AUTH_STORE_T store, mbedtls_x509_crt *cert)
{
	uint8_t *cert_buffer = NULL;
	int ret = 0;

	/* Allocate memory to read the CA certificate file */
	cert_buffer = k_malloc(CERT_BUFFER_SIZE);
	if (cert_buffer == NULL) {
		ret = -ENOMEM;
		goto done;
	}

	/* Load the certificate file */
	ret = load_file(store, LCZ_PKI_AUTH_FILE_DEVICE_CERTIFICATE, cert_buffer, CERT_BUFFER_SIZE);
	if (ret < 0) {
		goto done;
	}

	/* Parse the certificate */
	ret = mbedtls_x509_crt_parse(cert, cert_buffer, strlen(cert_buffer) + 1);
	if (ret < 0) {
		LOG_ERR("lcz_pki_auth_get_dev_cert: Could not parse device certificate: %d", ret);
		goto done;
	}

done:
	if (cert_buffer != NULL) {
		memset(cert_buffer, 0, CERT_BUFFER_SIZE);
		k_free(cert_buffer);
	}

	return ret;
}

int lcz_pki_auth_get_priv_key(LCZ_PKI_AUTH_STORE_T store, mbedtls_pk_context *key)
{
	uint8_t *key_buffer = NULL;
	int ret = 0;

	/* Allocate memory to read the CA certificate file */
	key_buffer = k_malloc(KEY_BUFFER_SIZE);
	if (key_buffer == NULL) {
		ret = -ENOMEM;
		goto done;
	}

	/* Load the certificate file */
	ret = load_file(store, LCZ_PKI_AUTH_FILE_PRIVATE_KEY, key_buffer, KEY_BUFFER_SIZE);
	if (ret < 0) {
		goto done;
	}

	/* Parse the key */
	ret = mbedtls_pk_parse_key(key, key_buffer, strlen(key_buffer) + 1, NULL, 0, rng, NULL);
	if (ret < 0) {
		LOG_ERR("lcz_pki_auth_get_priv_key: Could not parse private key: %d", ret);
		goto done;
	}

done:
	if (key_buffer != NULL) {
		memset(key_buffer, 0, KEY_BUFFER_SIZE);
		k_free(key_buffer);
	}

	return ret;
}

int lcz_pki_auth_pk_to_psa_key(mbedtls_pk_context *pk, psa_key_id_t *key)
{
	const mbedtls_ecp_keypair *ec;
	unsigned char d[MBEDTLS_ECP_MAX_BYTES];
	size_t d_len;
	psa_ecc_family_t curve_id;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_type_t key_type;
	size_t bits;
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

	/* export the private key material in the format PSA wants */
	if (mbedtls_pk_get_type(pk) != MBEDTLS_PK_ECKEY) {
		return (MBEDTLS_ERR_PK_TYPE_MISMATCH);
	}

	ec = mbedtls_pk_ec(*pk);
	d_len = PSA_BITS_TO_BYTES(ec->private_grp.nbits);
	if ((ret = mbedtls_mpi_write_binary(&ec->private_d, d, d_len)) != 0) {
		return (ret);
	}

	curve_id = mbedtls_ecc_group_to_psa(ec->private_grp.id, &bits);
	key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(curve_id);

	/* prepare the key attributes */
	psa_set_key_type(&attributes, key_type);
	psa_set_key_bits(&attributes, bits);
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);

	/* import private key into PSA */
	if (PSA_SUCCESS != psa_import_key(&attributes, d, d_len, key)) {
		return (MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED);
	}

	return 0;
}

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static int rng(void *context, unsigned char *data, size_t size)
{
	return (psa_generate_random(data, size) != PSA_SUCCESS);
}

static bool file_exists(LCZ_PKI_AUTH_STORE_T store, LCZ_PKI_AUTH_FILE_T file)
{
	uint8_t filename[FSU_MAX_ABS_PATH_SIZE];
	struct fs_dirent entry;
	int ret = -ENOENT;

	if (lcz_pki_auth_file_name_get(store, file, filename, sizeof(filename)) == 0) {
		ret = fs_stat(filename, &entry);
		if (ret == 0 && entry.type == FS_DIR_ENTRY_FILE) {
			return true;
		}
	}

	return false;
}

#if defined(CONFIG_TLS_CREDENTIALS)
static int file_size(LCZ_PKI_AUTH_STORE_T store, LCZ_PKI_AUTH_FILE_T file)
{
	uint8_t filename[FSU_MAX_ABS_PATH_SIZE];
	int ret = -ENOENT;

	if (lcz_pki_auth_file_name_get(store, file, filename, sizeof(filename)) == 0) {
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
		if (efs_is_encrypted_path(filename)) {
			ret = efs_get_file_size(filename);
		} else
#endif
		{
			ret = fsu_get_file_size_abs(filename);
		}
	}

	return ret;
}
#endif

static int load_file(LCZ_PKI_AUTH_STORE_T store, LCZ_PKI_AUTH_FILE_T file, uint8_t *buffer,
		     size_t buffer_size)
{
	char filename[FSU_MAX_ABS_PATH_SIZE];
	int ret = -ENOENT;

	if (lcz_pki_auth_file_name_get(store, file, filename, sizeof(filename)) == 0) {
#if defined(CONFIG_FSU_ENCRYPTED_FILES)
		if (efs_is_encrypted_path(filename)) {
			ret = efs_read(filename, buffer, buffer_size);
		} else
#endif
		{
			ret = fsu_read_abs(filename, buffer, buffer_size);
		}
		if (ret < 0) {
			LOG_ERR("load_file: Couldn't read file %s: %d", filename, ret);
		} else if (ret == buffer_size) {
			ret = -ENOMEM;
		} else {
			/* NUL-terminate the buffer */
			buffer[ret] = '\0';
		}
	}

	return ret;
}
