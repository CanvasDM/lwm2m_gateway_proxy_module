#
# Copyright (c) 2022 Laird Connectivity LLC
#
# SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
#

if(CONFIG_LCZ_LWM2M_GATEWAY_PROXY)

zephyr_include_directories(include)

zephyr_sources(
    src/lcz_lwm2m_gateway_proxy.c
    src/lcz_coap_helpers.c
    src/lcz_lwm2m_transport_ble_central.c
    )

zephyr_sources_ifdef(CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE
    src/lcz_lwm2m_gateway_proxy_file.c)

endif()
