#
# Copyright (c) 2022 Laird Connectivity LLC
#
# SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
#
if(CONFIG_LCZ_PKI_AUTH)

zephyr_include_directories(include)

zephyr_sources(src/lcz_pki_auth.c)
zephyr_sources_ifdef(CONFIG_LCZ_PKI_AUTH_SHELL
    src/lcz_pki_auth_shell.c
    )

endif()
