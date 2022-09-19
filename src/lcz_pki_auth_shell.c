/**
 * @file lcz_pki_auth_shell.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_pki_auth_shell, CONFIG_LCZ_PKI_AUTH_LOG_LEVEL);

#include <zephyr.h>
#include <shell/shell.h>

#include "lcz_pki_auth.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
static const struct {
	const char *name;
	LCZ_PKI_AUTH_STORE_T store;
} STORE_NAME_TO_STORE[LCZ_PKI_AUTH_STORE__NUM] = {
	{ "dm", LCZ_PKI_AUTH_STORE_DEVICE_MANAGEMENT },
	{ "tel", LCZ_PKI_AUTH_STORE_TELEMETRY },
	{ "p2p", LCZ_PKI_AUTH_STORE_PEER_TO_PEER },
	{ "fs", LCZ_PKI_AUTH_STORE_FILE_SERVICE },
};

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int cmd_pki_keygen(const struct shell *shell, size_t argc, char **argv);
static int cmd_pki_csrgen(const struct shell *shell, size_t argc, char **argv);
static int cmd_pki_status(const struct shell *shell, size_t argc, char **argv);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_pki, SHELL_CMD_ARG(keygen, NULL, "Generate key pair for store", cmd_pki_keygen, 2, 0),
	SHELL_CMD_ARG(csrgen, NULL,
		      "Generate CSR for store.\r\n"
		      "pki csrgen <store> <country> <org> <org_unit> <common_name>",
		      cmd_pki_csrgen, 6, 0),
	SHELL_CMD(status, NULL, "Display trust store status", cmd_pki_status),
	SHELL_SUBCMD_SET_END);
SHELL_CMD_REGISTER(pki, &sub_pki,
		   "PKI Utilities\r\n"
		   "Available trust/key stores:\r\n"
		   "dm  - device management\r\n"
		   "tel - telemetry\r\n"
		   "p2p - peer-to-peer\r\n"
		   "fs  - file service (firmware updates)",
		   NULL);

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static int cmd_pki_keygen(const struct shell *shell, size_t argc, char **argv)
{
	int ret;
	int i;

	for (i = 0; i < LCZ_PKI_AUTH_STORE__NUM; i++) {
		if (strcmp(argv[1], STORE_NAME_TO_STORE[i].name) == 0) {
			break;
		}
	}

	if (i >= LCZ_PKI_AUTH_STORE__NUM) {
		shell_error(shell, "Store name invalid");
		return -EINVAL;
	}

	ret = lcz_pki_auth_key_pair_gen(STORE_NAME_TO_STORE[i].store);
	if (ret == 0) {
		shell_print(shell, "Success");
	} else {
		shell_error(shell, "Failure %d", ret);
	}

	return ret;
}

static int cmd_pki_csrgen(const struct shell *shell, size_t argc, char **argv)
{
	int ret;
	int i;

	for (i = 0; i < LCZ_PKI_AUTH_STORE__NUM; i++) {
		if (strcmp(argv[1], STORE_NAME_TO_STORE[i].name) == 0) {
			break;
		}
	}

	if (i >= LCZ_PKI_AUTH_STORE__NUM) {
		shell_error(shell, "Store name invalid");
		return -EINVAL;
	}

	ret = lcz_pki_auth_csr_gen(STORE_NAME_TO_STORE[i].store, argv[2], argv[3], argv[4],
				   argv[5]);
	if (ret == 0) {
		shell_print(shell, "Success");
	} else {
		shell_error(shell, "Failure %d", ret);
	}

	return ret;
}

static int cmd_pki_status(const struct shell *shell, size_t argc, char **argv)
{
	int i;
	uint8_t flags;
	int ret = 0;

	for (i = 0; i < LCZ_PKI_AUTH_STORE__NUM; i++) {
		flags = lcz_pki_auth_store_status(STORE_NAME_TO_STORE[i].store);
		if (ret == 0 && flags != LCZ_PKI_AUTH_STATUS_GOOD) {
			ret = -EIO;
		}
		shell_print(shell, "%-3s %d %d %d %d %d %d %d %d %s", STORE_NAME_TO_STORE[i].name,
			    (flags >> 0) & 0x01, (flags >> 1) & 0x01, (flags >> 2) & 0x01,
			    (flags >> 3) & 0x01, (flags >> 4) & 0x01, (flags >> 5) & 0x01,
			    (flags >> 6) & 0x01, (flags >> 7) & 0x01,
			    (flags == LCZ_PKI_AUTH_STATUS_GOOD) ? "good" : "bad");
	}

	return ret;
}
