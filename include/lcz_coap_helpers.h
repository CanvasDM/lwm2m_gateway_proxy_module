/**
 * @file lcz_coap_helpers.h
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#ifndef __LCZ_COAP_HELPERS_H__
#define __LCZ_COAP_HELPERS_H__

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <stdint.h>
#include <zephyr/net/coap.h>

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Global Function Prototypes                                                                     */
/**************************************************************************************************/
/**
 * @brief Find a Proxy URI option in a CoAP packet
 *
 * This function searches a CoAP packet header for a Proxy URI option. If it finds one, it copies
 * it into the memory provided by uri and uri_len.
 *
 * @param[in] pkt CoAP packet to search
 * @param[out] uri Pointer to where URI should be written or NULL if the data isn't needed
 * @param[in] uri_len Size of the buffer pointed to by uri
 *
 * @returns true if a Proxy URI was found or false if not
 */
bool lcz_coap_find_proxy_uri(struct coap_packet *pkt, uint8_t *uri, int uri_len);

/**
 * @brief Get a CoAP option integer
 *
 * This function differs from the standard coap_get_option_int() in that it can handle a CoAP
 * packet containing large options (e.g., Proxy URI). The standard CoAP library cannot handle
 * these large options within a message without increasing CONFIG_COAP_EXTENDED_OPTIONS_LEN_VALUE
 * to an unreasonably high value.
 *
 * @param[in] pkt CoAP packet to search
 * @param[in] code Option code to find
 * @param[out] result Pointer to where the result should be stored or NULL if the data isn't needed
 *
 * @returns true if the requested option was found or false if not
 */
bool lcz_coap_get_option_int(struct coap_packet *pkt, int code, uint32_t *result);

/** @brief Strip the URI prefix from a CoAP message
 *
 * This function requires that the incoming CoAP packet have at least two UriPath options. The
 * function will remove the first, leaving the remaining ones.
 *
 * @param[in] pkt CoAP packet that needs to be stripped
 */
void lcz_coap_strip_uri_prefix(struct coap_packet *pkt);

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_COAP_HELPERS_H__ */
