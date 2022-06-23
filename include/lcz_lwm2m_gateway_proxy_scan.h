/**
 * @file lcz_lwm2m_gateway_proxy_scan.h
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#ifndef __LCZ_LWM2M_GATEWAY_PROXY_SCAN_H__
#define __LCZ_LWM2M_GATEWAY_PROXY_SCAN_H__

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Global Function Prototypes                                                                     */
/**************************************************************************************************/
/**
 * @brief Start scanning for BLE devices to proxy
 */
void lcz_lwm2m_gateway_proxy_scan_resume(void);

/**
 * @brief Stop scanning for BLE devices to proxy
 */
void lcz_lwm2m_gateway_proxy_scan_pause(void);

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_LWM2M_GATEWAY_PROXY_SCAN_H__ */
