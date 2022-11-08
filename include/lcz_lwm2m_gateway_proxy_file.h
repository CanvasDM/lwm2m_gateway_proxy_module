/**
 * @file lcz_lwm2m_gateway_proxy_file.h
 * @brief CoAP file proxy
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __LCZ_LWM2M_GATEWAY_PROXY_FILE_H
#define __LCZ_LWM2M_GATEWAY_PROXY_FILE_H

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <zephyr/net/coap.h>
#include <zephyr/net/lwm2m.h>

#include "lcz_lwm2m_gateway_proxy.h"

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Global Function Prototypes                                                                     */
/**************************************************************************************************/
/** @brief Initialize the CoAP file proxy cache
 */
void lcz_lwm2m_gateway_file_proxy_init(void);

/** @brief Handle an incoming CoAP file proxy request
 *
 * @param[in] pctx LwM2M proxy context for device making request
 * @param[in] request Incoming CoAP packet
 * @param[out] ack Reply packet (if available)
 *
 * @returns LWM2M_COAP_RESP_NONE if not sending a reply now or LWM2M_COAP_RESP_ACK
 * if the ack reply packet is populated and ready to send.
 */
enum lwm2m_coap_resp lcz_lwm2m_gateway_file_proxy_request(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx,
							  struct coap_packet *request,
							  struct coap_packet *ack);

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_LWM2M_GATEWAY_PROXY_FILE_H */
