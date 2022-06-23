/**
 * @file lcz_coap_helpers.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_coap_helpers, CONFIG_LCZ_LWM2M_GATEWAY_PROXY_LOG_LEVEL);

#include <stdint.h>
#include <zephyr.h>
#include <sys/byteorder.h>
#include <net/coap.h>

#include "lcz_coap_helpers.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define DELTA_LEN_DELTA_MASK 0xF0
#define DELTA_LEN_LEN_MASK 0x0F

#define DELTA_LEN_DELTA(x) ((x) >> 4)
#define DELTA_LEN_LEN(x) ((x)&DELTA_LEN_LEN_MASK)

#define DELTA_ONE_BYTE 13
#define DELTA_TWO_BYTES 14
#define DELTA_END 15

#define DELTA_ONE_BYTE_OFFSET 13
#define DELTA_TWO_BYTES_OFFSET 269

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
bool lcz_coap_find_proxy_uri(struct coap_packet *pkt, uint8_t *uri, int uri_len)
{
	int i;
	uint8_t delta_len;
	uint16_t delta;
	uint16_t len;
	uint16_t option_code = 0;
	bool ret = false;

	i = pkt->hdr_len;
	while (i < pkt->offset) {
		delta_len = pkt->data[i++];

		/* Decode the option delta */
		if (DELTA_LEN_DELTA(delta_len) == DELTA_ONE_BYTE) {
			delta = pkt->data[i] + DELTA_ONE_BYTE_OFFSET;
			i++;
		} else if (DELTA_LEN_DELTA(delta_len) == DELTA_TWO_BYTES) {
			delta = sys_get_be16(pkt->data + i) + DELTA_TWO_BYTES_OFFSET;
			i += 2;
		} else if (DELTA_LEN_DELTA(delta_len) == DELTA_END) {
			/* End of options marker */
			break;
		} else {
			delta = DELTA_LEN_DELTA(delta_len);
		}

		/* Decode the option length */
		if (DELTA_LEN_LEN(delta_len) == DELTA_ONE_BYTE) {
			len = pkt->data[i] + DELTA_ONE_BYTE_OFFSET;
			i++;
		} else if (DELTA_LEN_LEN(delta_len) == DELTA_TWO_BYTES) {
			len = sys_get_be16(pkt->data + i) + DELTA_TWO_BYTES_OFFSET;
			i += 2;
		} else if (DELTA_LEN_LEN(delta_len) == DELTA_END) {
			/* Error */
			break;
		} else {
			len = DELTA_LEN_LEN(delta_len);
		}

		/* Check for the proxy URI option */
		if ((option_code + delta) == COAP_OPTION_PROXY_URI && (i + len) <= pkt->offset) {
			/* We found the option we were looking for */
			ret = true;

			/* Copy the proxy URI into the data pointer provided */
			if (uri != NULL) {
				/* Make sure that the URI can fit */
				if (len > (uri_len - 1)) {
					LOG_ERR("URI (%d) cannot fit into provided buffer (%d)",
						len, uri_len);
					ret = false;
				} else {
					memcpy(uri, pkt->data + i, len);
					uri[len] = '\0';
				}
			}

			/* No point in continuing since we found one */
			break;
		}

		/* Update the option code for the next option */
		option_code += delta;
		i += len;
	}

	return ret;
}

bool lcz_coap_get_option_int(struct coap_packet *pkt, int code, uint32_t *result)
{
	int i;
	uint8_t delta_len;
	uint16_t delta;
	uint16_t len;
	uint16_t option_code = 0;
	bool ret = false;

	i = pkt->hdr_len;
	while (i < pkt->offset) {
		delta_len = pkt->data[i++];

		/* Decode the option delta */
		if (DELTA_LEN_DELTA(delta_len) == DELTA_ONE_BYTE) {
			delta = pkt->data[i] + DELTA_ONE_BYTE_OFFSET;
			i++;
		} else if (DELTA_LEN_DELTA(delta_len) == DELTA_TWO_BYTES) {
			delta = sys_get_be16(pkt->data + i) + DELTA_TWO_BYTES_OFFSET;
			i += 2;
		} else if (DELTA_LEN_DELTA(delta_len) == DELTA_END) {
			/* End of options marker */
			break;
		} else {
			delta = DELTA_LEN_DELTA(delta_len);
		}

		/* Decode the option length */
		if (DELTA_LEN_LEN(delta_len) == DELTA_ONE_BYTE) {
			len = pkt->data[i] + DELTA_ONE_BYTE_OFFSET;
			i++;
		} else if (DELTA_LEN_LEN(delta_len) == DELTA_TWO_BYTES) {
			len = sys_get_be16(pkt->data + i) + DELTA_TWO_BYTES_OFFSET;
			i += 2;
		} else if (DELTA_LEN_LEN(delta_len) == DELTA_END) {
			/* Error */
			break;
		} else {
			len = DELTA_LEN_LEN(delta_len);
		}

		/* Check for the proxy URI option */
		if ((option_code + delta) == code && (i + len) <= pkt->offset) {
			/* We found the option we were looking for */
			ret = true;

			/* Copy the option data into the data pointer provided */
			if (result != NULL) {
				if (len == 1) {
					*result = pkt->data[i];
				} else if (len == 2) {
					*result = sys_get_be16(pkt->data + i);
				} else if (len == 3) {
					*result = sys_get_be24(pkt->data + i);
				} else if (len == 4) {
					*result = sys_get_be32(pkt->data + i);
				} else {
					*result = 0;
				}
			}

			/* No point in continuing since we found one */
			break;
		}

		/* Update the option code for the next option */
		option_code += delta;
		i += len;
	}

	return ret;
}

/** @brief Strip the URI prefix from a CoAP message
 *
 * This function requires that the incoming CoAP packet have at least
 * two UriPath options. The function will remove the first, leaving
 * the remaining ones.
 *
 * @param[in] pkt CoAP packet that needs to be stripped
 */
void lcz_coap_strip_uri_prefix(struct coap_packet *pkt)
{
	int i;
	int start_idx = -1;
	uint8_t delta_len;
	uint16_t delta;
	uint16_t len;
	uint16_t option_code = 0;
	int delta_len_bytes;

	i = pkt->hdr_len;
	while (i < pkt->offset) {
		start_idx = i;
		delta_len = pkt->data[i++];
		delta_len_bytes = 1;

		/* Decode the option delta */
		if (DELTA_LEN_DELTA(delta_len) > COAP_OPTION_URI_PATH) {
			/* This delta is larger than the value we're looking for,
			 * so there's no point in continuing. */
			break;
		} else {
			delta = DELTA_LEN_DELTA(delta_len);
		}

		/* Decode the option length */
		if (DELTA_LEN_LEN(delta_len) == DELTA_ONE_BYTE) {
			len = pkt->data[i] + DELTA_ONE_BYTE_OFFSET;
			delta_len_bytes += 1;
			i++;
		} else if (DELTA_LEN_LEN(delta_len) == DELTA_TWO_BYTES) {
			len = sys_get_be16(pkt->data + i) + DELTA_TWO_BYTES_OFFSET;
			delta_len_bytes += 2;
			i += 2;
		} else if (DELTA_LEN_LEN(delta_len) == DELTA_END) {
			/* Error */
			break;
		} else {
			len = DELTA_LEN_LEN(delta_len);
		}

		/* Check for the first URI Path option */
		if ((option_code + delta) == COAP_OPTION_URI_PATH) {
			/* Remove the URI Path */
			memmove(pkt->data + start_idx, pkt->data + i + len,
				pkt->offset - (len + delta_len_bytes));

			/* Udpate the delta in the next option */
			pkt->data[start_idx] &= ~DELTA_LEN_DELTA_MASK;
			pkt->data[start_idx] |= delta_len & DELTA_LEN_DELTA_MASK;

			/* Adjust the lengths in the packet structure */
			pkt->opt_len -= (len + delta_len_bytes);
			pkt->offset -= (len + delta_len_bytes);

			/* We're done */
			break;
		}

		/* Update the option code for the next option */
		option_code += delta;
		i += len;
	}
}
