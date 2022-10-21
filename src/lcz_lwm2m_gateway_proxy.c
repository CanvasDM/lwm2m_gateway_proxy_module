/**
 * @file lcz_lwm2m_gateway_proxy.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_lwm2m_gateway_proxy, CONFIG_LCZ_LWM2M_GATEWAY_PROXY_LOG_LEVEL);

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zephyr.h>
#include <init.h>
#include <bluetooth/addr.h>
#include <random/rand32.h>
#include <net/coap.h>
#include <lwm2m_obj_gateway.h>
#include <lcz_lwm2m.h>

#include "lcz_coap_helpers.h"
#include "lcz_lwm2m_client.h"
#include "lcz_lwm2m_gateway_obj.h"
#include "lcz_lwm2m_gateway_proxy_file.h"
#include "lcz_lwm2m_gateway_proxy.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define REGISTRATION_PATH "rd"
#define LIFETIME_QUERY_STRING "lt="
#define ENDPOINT_QUERY_STRING "ep="

#define REGISTRATION_NUM_PATHS 1
#define REGISTRATION_UPDATE_NUM_PATHS 2

#define COAP_OPTIONS_NUM 8

/* We don't retry any of the proxied CoAP messages, but need to init the retries field */
#define COAP_RETRIES_INIT 1

#define CTX_IDX_INVALID -1
#define INVALID_SOCKET -1

#define LIFETIME_STRING_MAX 32

/* Limit to the tunnel ID to 31 bits */
#define TUNNEL_ID_MASK 0x7FFFFFFF

struct coap_queue_entry_t {
	void *fifo_reserved;
	struct coap_packet pkt;
	uint8_t pkt_data[1]; /* Variable-sized array */
};

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_lwm2m_gateway_proxy_init(const struct device *device);
static void reset_conn_timer(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx);
static int find_open_context(void);
static void lwm2m_client_connected(struct lwm2m_ctx *client, int lwm2m_client_index, bool connected,
				   enum lwm2m_rd_client_event event);
static uint16_t parse_lifetime(uint8_t *option_value, int option_len);
static enum lwm2m_coap_resp handle_registration(struct lwm2m_ctx *client_ctx,
						struct coap_packet *request,
						struct coap_packet *ack);
static enum lwm2m_coap_resp handle_registration_update(struct lwm2m_ctx *client_ctx,
						       struct coap_packet *request,
						       struct coap_packet *ack);
static void forward_prefixed_message(int dev_idx, struct coap_packet *pkt);
static void forward_reply_message(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, struct coap_packet *pkt);
static void forward_sensor_reply(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, struct coap_packet *pkt);
static enum lwm2m_coap_resp transport_coap_msg_cb(struct lwm2m_ctx *client_ctx,
						  struct coap_packet *request,
						  struct coap_packet *ack);
static int start_context(int ctx_idx, int dev_idx, uint8_t flags);
static int add_to_queue(struct k_fifo *queue, struct coap_packet *pkt);
static void conn_timeout_work_handler(struct k_work *work);
static void transport_fault_cb(struct lwm2m_ctx *ctx, int error);
static int dev_idx_to_ctx_idx(int dev_idx);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static K_MUTEX_DEFINE(proxy_mutex);
static LCZ_LWM2M_GATEWAY_PROXY_CTX_T proxy_ctx[CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS];

static struct lwm2m_ctx *server_context = NULL;

static struct lcz_lwm2m_client_event_callback_agent lwm2m_event_agent = {
	.event_callback = NULL,
	.connected_callback = lwm2m_client_connected
};

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
LCZ_LWM2M_GATEWAY_PROXY_CTX_T *lcz_lwm2m_gateway_proxy_conn_to_context(struct bt_conn *conn)
{
	int i;

	/* Find a matching connection handle */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS; i++) {
		if (((proxy_ctx[i].flags & CTX_FLAG_ACTIVE) != 0) &&
		    (proxy_ctx[i].active_conn == conn)) {
			break;
		}
	}

	/* Return what we found */
	if (i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS) {
		return &(proxy_ctx[i]);
	} else {
		return NULL;
	}
}

LCZ_LWM2M_GATEWAY_PROXY_CTX_T *lcz_lwm2m_gateway_proxy_addr_to_context(const bt_addr_le_t *addr)
{
	int i;

	/* Find a matching connection handle */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS; i++) {
		if (((proxy_ctx[i].flags & CTX_FLAG_ACTIVE) != 0) &&
		    (memcmp(addr, bt_conn_get_dst(proxy_ctx[i].active_conn),
			    sizeof(bt_addr_le_t)) == 0)) {
			break;
		}
	}

	/* Return what we found */
	if (i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS) {
		return &(proxy_ctx[i]);
	} else {
		return NULL;
	}
}

void lcz_lwm2m_gateway_proxy_device_ready(const bt_addr_le_t *addr, bool coded_phy)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;
	int dev_idx;
	int ctx_idx;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&proxy_mutex, K_FOREVER);

	/* Find the device in the object database */
	dev_idx = lcz_lwm2m_gw_obj_lookup_ble(addr);

	/* If we didn't find the device in our database, try to add it */
	if (dev_idx < 0) {
		dev_idx = lcz_lwm2m_gw_obj_create(addr);
	}

	if (dev_idx != DEV_IDX_INVALID) {
		/* Allocate our DM-specific data for the device if we haven't yet */
		pdev = lcz_lwm2m_gw_obj_get_dm_data(dev_idx);
		if (pdev == NULL) {
			/* Allocate memory for DM-specific data */
			pdev = (LCZ_LWM2M_GATEWAY_PROXY_DEV_T *)k_malloc(
				sizeof(LCZ_LWM2M_GATEWAY_PROXY_DEV_T));
			if (pdev == NULL) {
				LOG_ERR("Failed to allocate DM device data");
				dev_idx = DEV_IDX_INVALID;
			} else {
				/* Generate a new random tunnel ID for this device */
				sys_rand_get(&(pdev->tunnel_id), sizeof(pdev->tunnel_id));

				/* Limit tunnel ID to 31 bits */
				pdev->tunnel_id &= TUNNEL_ID_MASK;

				/* Reset the failure count */
				pdev->failure_count = 0;

				/* Initialize the TX queue */
				k_fifo_init(&(pdev->tx_queue));

				/* Attach the DM-specific data to the gateway object */
				lcz_lwm2m_gw_obj_set_dm_data(dev_idx, pdev);
			}
		}

		/* Store the current device PHY in the device record */
		if (pdev != NULL) {
			pdev->coded_phy = coded_phy;
		}
	}

	if (dev_idx != DEV_IDX_INVALID) {
		/* See if we already have an open context for this device (unlikely) */
		ctx_idx = dev_idx_to_ctx_idx(dev_idx);

		/* If no existing context, try to open one */
		if (ctx_idx == CTX_IDX_INVALID) {
			/* Check to see if we have an open context to use for this device */
			ctx_idx = find_open_context();
			if (ctx_idx >= 0) {
				start_context(ctx_idx, dev_idx, CTX_FLAG_INCOMING);
			}
		}
	}

	/* Release the mutex */
	k_mutex_unlock(&proxy_mutex);
}

void foreach_pending_tx(int idx, void *dm_ptr, void *telem_ptr, void *priv)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev = (LCZ_LWM2M_GATEWAY_PROXY_DEV_T *)dm_ptr;
	int *dev_idx_ptr = (int *)priv;

	/* Find the first device that has a non-empty FIFO */
	if (dev_idx_ptr != NULL && *dev_idx_ptr == DEV_IDX_INVALID && pdev != NULL) {
		if (!k_fifo_is_empty(&(pdev->tx_queue))) {
			*dev_idx_ptr = idx;
		}
	}
}

void lcz_lwm2m_gateway_proxy_close(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx)
{
	int dev_idx;
	int ctx_idx = (pctx - proxy_ctx) / sizeof(proxy_ctx[0]);
	struct coap_queue_entry_t *item;
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&proxy_mutex, K_FOREVER);

	LOG_INF("Proxy context %d closed", ctx_idx);

	if (pctx != NULL) {
		k_mutex_lock(&(pctx->lock), K_FOREVER);

		k_work_cancel_delayable(&(pctx->conn_timeout_work));

		pctx->dev_idx = DEV_IDX_INVALID;
		pctx->flags = 0;

		k_mutex_unlock(&(pctx->lock));
	}

	/* Try to find a device that has pending data in its queue */
	dev_idx = DEV_IDX_INVALID;
	(void)lcz_lwm2m_gw_obj_foreach(foreach_pending_tx, &dev_idx);

	/* Conect to the device and send the contents of the TX queue */
	if (dev_idx != DEV_IDX_INVALID) {
		pdev = lcz_lwm2m_gw_obj_get_dm_data(dev_idx);

		if (start_context(ctx_idx, dev_idx, 0) == 0) {
			do {
				item = k_fifo_get(&(pdev->tx_queue), K_NO_WAIT);
				if (item != NULL) {
					lwm2m_engine_send_coap(&(proxy_ctx[ctx_idx].ctx),
							       &(item->pkt));
					k_free(item);
				}
			} while (item != NULL);
		}
	}

	/* Release the mutex */
	k_mutex_unlock(&proxy_mutex);
}

void lcz_lwm2m_gateway_proxy_add_context(struct lwm2m_ctx *ctx)
{
	ctx->coap_msg_cb = transport_coap_msg_cb;
}

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
/** @brief Reset the connection timer for a proxy context
 *
 * @param[in] pctx Proxy context to reset
 */
static void reset_conn_timer(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx)
{
	k_timeout_t timeout = K_SECONDS(CONFIG_LCZ_LWM2M_GATEWAY_PROXY_TIMEOUT_OUTGOING_SECONDS);

	if ((pctx->flags & CTX_FLAG_INCOMING) != 0) {
		timeout = K_SECONDS(CONFIG_LCZ_LWM2M_GATEWAY_PROXY_TIMEOUT_INCOMING_SECONDS);
	}

	k_work_reschedule(&(pctx->conn_timeout_work), timeout);
}

/** @brief Find an available proxy context
 *
 * @returns a positive proxy context index or <0 if none are available
 */
static int find_open_context(void)
{
	int i;

	/* Search our array for an open context */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS; i++) {
		if ((proxy_ctx[i].flags & (CTX_FLAG_ACTIVE | CTX_FLAG_STOPPED)) == 0) {
			break;
		}
	}

	/* Return a negative error if we didn't find an available context */
	if (i >= CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS) {
		i = CTX_IDX_INVALID;
	}

	return i;
}

/** @brief Callback for LwM2M registration client events
 *
 * This callback is called by the LwM2M client module when the connection state
 * changes. If the primary DM LwM2M connection goes down, all client connections
 * are closed. If the primary DM LwM2M connection comes up, client connections are
 * re-enabled.
 *
 * @param[in] client LwM2M engine context
 * @param[in] lwm2m_client_index LwM2M client index
 * @param[in] connnected true if the connection is connected, false if not
 * @param[in] event LwM2M RD client event that caused the state change
 */
static void lwm2m_client_connected(struct lwm2m_ctx *client, int lwm2m_client_index, bool connected,
				   enum lwm2m_rd_client_event event)
{
	int i;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&proxy_mutex, K_FOREVER);

	/* Only look for the DM client events */
	if (client != NULL && lwm2m_client_index == CONFIG_LCZ_BLE_GW_DM_CLIENT_INDEX) {
		if (connected) {
			/* Save the server LwM2M context */
			server_context = client;

			/* Register our CoAP message handler with the transport */
			server_context->coap_msg_cb = transport_coap_msg_cb;

			/* Unblock the client contexts */
			for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS; i++) {
				if ((proxy_ctx[i].flags & CTX_FLAG_STOPPED) != 0) {
					proxy_ctx[i].flags = 0;
				}
			}
		} else {
			/* Block the client contexts */
			for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS; i++) {
				/* If the context is available, block it */
				if ((proxy_ctx[i].flags & CTX_FLAG_ACTIVE) == 0) {
					proxy_ctx[i].flags = CTX_FLAG_STOPPED;
				} else {
					/* Else, close the open context before blocking it */

					/* Close the context and transport */
					lwm2m_engine_context_close(&(proxy_ctx[i].ctx));

					/*
					 * Engine context close will call the BLE central transport close function,
					 * which will call our lcz_lwm2m_gateway_proxy_close() function to release
					 * the proxy context data structure.
				 	 */

					/* Block the context */
					proxy_ctx[i].flags = CTX_FLAG_STOPPED;
				}
			}
		}
	}

	/* Release the mutex */
	k_mutex_unlock(&proxy_mutex);
}

/** @brief Parse the lifetime parameter from a registration (update)
 *
 * @param[in] option_value Pointer string holding the lifetime value
 * @param[in] option_len Length of the string
 *
 * @returns Parsed lifetime bounded by configured min/max lifetimes
 */
static uint16_t parse_lifetime(uint8_t *option_value, int option_len)
{
	uint8_t option_string[LIFETIME_STRING_MAX];
	unsigned long lt = 0;

	/* Copy the option string so that we can NUL-terminate it */
	memset(option_string, 0, sizeof(option_string));
	if (option_len <= (sizeof(option_string) - 1)) {
		memcpy(option_string, option_value, option_len);

		/* Parse the timeout value from the input string */
		lt = strtoul(option_value, NULL, 10);
	} else {
		LOG_ERR("Lifetime string (%d) is too long (%d)", option_len, sizeof(option_string));
	}

	/* Limit the registration lifetime */
	if (lt < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_MIN_CLIENT_LIFETIME_SECONDS) {
		lt = CONFIG_LCZ_LWM2M_GATEWAY_PROXY_MIN_CLIENT_LIFETIME_SECONDS;
	} else if (lt > CONFIG_LCZ_LWM2M_GATEWAY_PROXY_MAX_CLIENT_LIFETIME_SECONDS) {
		lt = CONFIG_LCZ_LWM2M_GATEWAY_PROXY_MAX_CLIENT_LIFETIME_SECONDS;
	}

	/* Add a small grace period to avoid premature timeouts */
	return lt + CONFIG_LCZ_LWM2M_SECONDS_TO_UPDATE_EARLY;
}

/** @brief Handle a registration message from a client
 *
 * @param[in] client_ctx LwM2M client context on which the message was received
 * @param[in] request Received CoAP message
 * @param[out] ack Pointer to CoAP ACK message to be used as the resplt
 *
 * @returns LWM2M_COAP_RESP_NONE if no reply should be sent, LWM2M_COAP_RESP_ACK if
 * the CoAP ACK message was populated and should be sent as a reply, or
 * LWM2M_COAP_RESP_NOT_HANDLED if the received CoAP message was not processed and
 * the LwM2M engine should attempt to process it.
 */
static enum lwm2m_coap_resp handle_registration(struct lwm2m_ctx *client_ctx,
						struct coap_packet *request,
						struct coap_packet *ack)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx;
	static struct coap_option options[COAP_OPTIONS_NUM];
	int n;
	int i;
	const uint8_t *corelnk;
	uint16_t corelnk_len;
	char *prefix;

	if (client_ctx == server_context || ack == NULL) {
		/* Let the engine deal with this (likely returns 4.4 error) */
		return LWM2M_COAP_RESP_NOT_HANDLED;
	} else {
		/* Get our proxy context for the client */
		pctx = CONTAINER_OF(client_ctx, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, ctx);

		/* Update the response code */
		ack->data[COAP_REPLY_BYTE] = COAP_RESPONSE_CODE_CREATED;

		/* Extract options from the registration request */
		memset(options, 0, sizeof(options));
		n = coap_find_options(request, COAP_OPTION_URI_QUERY, options, ARRAY_SIZE(options));
		for (i = 0; i < n; i++) {
			if (options[i].len > strlen(LIFETIME_QUERY_STRING) &&
			    strncmp(options[i].value, LIFETIME_QUERY_STRING,
				    strlen(LIFETIME_QUERY_STRING)) == 0) {
				lcz_lwm2m_gw_obj_set_lifetime(
					pctx->dev_idx,
					parse_lifetime(
						options[i].value + strlen(LIFETIME_QUERY_STRING),
						options[i].len - strlen(LIFETIME_QUERY_STRING)));
			} else if (options[i].len > strlen(ENDPOINT_QUERY_STRING) &&
				   strncmp(options[i].value, ENDPOINT_QUERY_STRING,
					   strlen(ENDPOINT_QUERY_STRING)) == 0) {
				lcz_lwm2m_gw_obj_set_endpoint_name(
					pctx->dev_idx,
					options[i].value + strlen(ENDPOINT_QUERY_STRING),
					options[i].len - strlen(ENDPOINT_QUERY_STRING));
			}
		}

		/* Extract CoreLnk string from the body of the POST */
		corelnk = coap_packet_get_payload(request, &corelnk_len);
		lcz_lwm2m_gw_obj_set_object_list(pctx->dev_idx, (char *)corelnk, corelnk_len);

		/* Update the expiration time for the device */
		lcz_lwm2m_gw_obj_tick(pctx->dev_idx);

		/* Get the endpoint for the device */
		prefix = lcz_lwm2m_gw_obj_get_prefix(pctx->dev_idx);

		/* Add the Location paths to the CoAP message */
		coap_packet_append_option(ack, COAP_OPTION_LOCATION_PATH, REGISTRATION_PATH,
					  strlen(REGISTRATION_PATH));

		/* Use the prefix as the registration identifer back to the client */
		coap_packet_append_option(ack, COAP_OPTION_LOCATION_PATH, prefix, strlen(prefix));

		/* Send the ACK that we built */
		return LWM2M_COAP_RESP_ACK;
	}
}

/** @brief Handle a registration update message from a client
 *
 * @param[in] client_ctx LwM2M client context on which the message was received
 * @param[in] request Received CoAP message
 * @param[out] ack Pointer to CoAP ACK message to be used as the reply
 *
 * @returns LWM2M_COAP_RESP_NONE if no reply should be sent, LWM2M_COAP_RESP_ACK if
 * the CoAP ACK message was populated and should be sent as a reply, or
 * LWM2M_COAP_RESP_NOT_HANDLED if the received CoAP message was not processed and
 * the LwM2M engine should attempt to process it.
 */
static enum lwm2m_coap_resp handle_registration_update(struct lwm2m_ctx *client_ctx,
						       struct coap_packet *request,
						       struct coap_packet *ack)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx;
	static struct coap_option options[COAP_OPTIONS_NUM];
	int n;
	int i;
	char *prefix;
	const uint8_t *corelnk;
	uint16_t corelnk_len;

	/* parse the URL path into components */
	memset(options, 0, sizeof(options));
	n = coap_find_options(request, COAP_OPTION_URI_PATH, options, ARRAY_SIZE(options));

	if (client_ctx == server_context || ack == NULL) {
		/* Let the engine deal with this (likely returns 4.4 error) */
		return LWM2M_COAP_RESP_NOT_HANDLED;
	} else {
		/* Get our proxy context for the client */
		pctx = CONTAINER_OF(client_ctx, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, ctx);

		/* Get the endpoint for the device */
		prefix = lcz_lwm2m_gw_obj_get_prefix(pctx->dev_idx);

		/* Ensure that the correct prefix is being used */
		if (prefix != NULL && options[1].len == strlen(prefix) &&
		    strncmp(options[1].value, prefix, options[1].len) == 0) {
			/* Handle updated registration lifetime value */
			memset(options, 0, sizeof(options));
			n = coap_find_options(request, COAP_OPTION_URI_QUERY, options,
					      ARRAY_SIZE(options));
			for (i = 0; i < n; i++) {
				if (options[i].len > strlen(LIFETIME_QUERY_STRING) &&
				    strncmp(options[i].value, LIFETIME_QUERY_STRING,
					    strlen(LIFETIME_QUERY_STRING)) == 0) {
					lcz_lwm2m_gw_obj_set_lifetime(
						pctx->dev_idx,
						parse_lifetime(
							options[i].value +
								strlen(LIFETIME_QUERY_STRING),
							options[i].len -
								strlen(LIFETIME_QUERY_STRING)));
				}
			}

			/* Extract CoreLnk string from the body of the POST */
			corelnk = coap_packet_get_payload(request, &corelnk_len);
			if (corelnk != NULL && corelnk_len > 0) {
				lcz_lwm2m_gw_obj_set_object_list(pctx->dev_idx, (char *)corelnk,
								 corelnk_len);
			}

			/* Update the expiration time for the device */
			lcz_lwm2m_gw_obj_tick(pctx->dev_idx);

			/* "Changed" is the correct response */
			ack->data[COAP_REPLY_BYTE] = COAP_RESPONSE_CODE_CHANGED;
		} else {
			/* Prefix was invalid. Return "Not found" */
			ack->data[COAP_REPLY_BYTE] = COAP_RESPONSE_CODE_NOT_FOUND;
		}

		/* No additional CoAP message contents are needed */

		/* Send the ACK that we built */
		return LWM2M_COAP_RESP_ACK;
	}
}

/** @brief Forward a CoAP message with a prefix to a client device
 *
 * This function will remove the first UriPath option from the message and then
 * send the received message to the client device.
 *
 * @param[in] dev_idx Device to which the message should be sent
 * @param[in] pkt Recevied CoAP message
 */
static void forward_prefixed_message(int dev_idx, struct coap_packet *pkt)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev = lcz_lwm2m_gw_obj_get_dm_data(dev_idx);
	int ctx_idx;

	/* Unlikely, but if we haven't talked with this device yet, don't forward */
	if (pdev == NULL) {
		return;
	}

	/* Edit the message to remove the prefix */
	lcz_coap_strip_uri_prefix(pkt);

	/* Find the context associated with the device */
	ctx_idx = dev_idx_to_ctx_idx(dev_idx);

	/* If no current context, see if a context can be created */
	if (ctx_idx == CTX_IDX_INVALID) {
		ctx_idx = find_open_context();
		if (ctx_idx >= 0 && start_context(ctx_idx, dev_idx, 0) < 0) {
			ctx_idx = CTX_IDX_INVALID;
		}
	}

	/* If a context cannot be created, add the message to the device's FIFO */
	if (ctx_idx == CTX_IDX_INVALID) {
		if (pdev != NULL) {
			/* Add the packet to the device's queue */
			add_to_queue(&(pdev->tx_queue), pkt);
		}
	}

	/* Else, send the message to the sensor */
	else {
		lwm2m_engine_send_coap(&(proxy_ctx[ctx_idx].ctx), pkt);
	}
}

/** @brief Forward a reply from the server to a client device
 *
 * @param[in] pctx Proxy context to which the message should be sent
 * @param[in] pkt Received CoAP message
 */
static void forward_reply_message(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, struct coap_packet *pkt)
{
	lwm2m_engine_send_coap(&(pctx->ctx), pkt);
}

/** @brief Forward a reply from a client device to the server
 *
 * @param[in] pctx Proxy context from which the message was received
 * @param[in] pkt Received CoAP message
 */
static void forward_sensor_reply(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, struct coap_packet *pkt)
{
	struct coap_pending *pending;
	int ret;

	/* Send the packet to the server */
	lwm2m_engine_send_coap(server_context, pkt);

	/* If this message expects an ACK from the server, add it to a pending list */
	if (coap_header_get_type(pkt) == COAP_TYPE_CON) {
		pending = coap_pending_next_unused(pctx->pendings,
						   CONFIG_LCZ_LWM2M_ENGINE_MAX_PENDING);
		if (pending == NULL) {
			LOG_ERR("Unable to find free pending slot");
		} else {
			ret = coap_pending_init(pending, pkt, NULL, COAP_RETRIES_INIT);
			if (ret < 0) {
				LOG_ERR("Unable to initialize pending: %d", ret);
			}
			coap_pending_cycle(pending);
		}
	}
}

/** @brief Callback function for received CoAP messages on a LwM2M context
 *
 * On LwM2M contexts for which this callback is registered, this callback is
 * called for each received CoAP message. This is done prior to any other
 * handling in the LwM2M engine to give the callback a chance to decide to
 * handle the message or not.
 *
 * @param[in] client_ctx LwM2M context on which the message was received
 * @param[in] request Received CoAP message
 * @param[out] ack Pointer to CoAP ACK message to be used as the reply
 *
 * @returns LWM2M_COAP_RESP_NONE if no reply should be sent, LWM2M_COAP_RESP_ACK if
 * the CoAP ACK message was populated and should be sent as a reply, or
 * LWM2M_COAP_RESP_NOT_HANDLED if the received CoAP message was not processed and
 * the LwM2M engine should attempt to process it.
 */
static enum lwm2m_coap_resp transport_coap_msg_cb(struct lwm2m_ctx *client_ctx,
						  struct coap_packet *request,
						  struct coap_packet *ack)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx;
	enum lwm2m_coap_resp ret = LWM2M_COAP_RESP_NOT_HANDLED;
	static struct coap_option options[COAP_OPTIONS_NUM];
	int n;
	int i;
	uint8_t code;
	uint16_t format = 0;
	bool is_proxy_uri;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&proxy_mutex, K_FOREVER);

	/* Get our proxy context for the client */
	pctx = NULL;
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS; i++) {
		if (((proxy_ctx[i].flags & CTX_FLAG_ACTIVE) != 0) &&
		    &(proxy_ctx[i].ctx) == client_ctx) {
			/* Save a pointer to the context */
			pctx = &(proxy_ctx[i]);

			/* Reset the timer for this connection */
			reset_conn_timer(pctx);
			break;
		}
	}

	/* Get the request code */
	code = coap_header_get_code(request);

	/* Read Content Format */
	memset(options, 0, sizeof(options));
	n = coap_find_options(request, COAP_OPTION_CONTENT_FORMAT, options, ARRAY_SIZE(options));
	if (n > 0) {
		format = coap_option_value_to_int(&options[0]);
	}

	/* Parse the URL path into components */
	memset(options, 0, sizeof(options));
	n = coap_find_options(request, COAP_OPTION_URI_PATH, options, ARRAY_SIZE(options));

	/* Check for a Proxy URI option */
	is_proxy_uri = lcz_coap_find_proxy_uri(request, NULL, 0);

	/* Check for a POST to /rd for a registration */
	if (code == COAP_METHOD_POST && format == COAP_CONTENT_FORMAT_APP_LINK_FORMAT &&
	    n == REGISTRATION_NUM_PATHS && options[0].len == strlen(REGISTRATION_PATH) &&
	    strncmp(options[0].value, REGISTRATION_PATH, strlen(REGISTRATION_PATH)) == 0) {
		ret = handle_registration(client_ctx, request, ack);
	}

	/* Check for a POST to /rd/<prefix> for a registration update */
	else if (code == COAP_METHOD_POST && n == REGISTRATION_UPDATE_NUM_PATHS &&
		 options[0].len == strlen(REGISTRATION_PATH) &&
		 strncmp(options[0].value, REGISTRATION_PATH, strlen(REGISTRATION_PATH)) == 0) {
		ret = handle_registration_update(client_ctx, request, ack);
	}

	/* Check for a CoAP proxy request from a sensor */
	else if (pctx != NULL && is_proxy_uri) {
#if defined(CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE)
		/* Handle proxy request */
		ret = lcz_lwm2m_gateway_file_proxy_request(pctx, request, ack);
#else
		/* Do nothing else with the message in this context */
		ret = LWM2M_COAP_RESP_NONE;
		LOG_ERR("Unhandled CoAP File Proxy request");
#endif
	}

	/* Check for a known prefix from the server */
	else if (pctx == NULL && n > 1) {
		uint8_t prefix[CONFIG_LCZ_LWM2M_GATEWAY_PREFIX_MAX_STR_SIZE + 1];

		/* Copy and nul-terminate the prefix string */
		if (options[0].len > CONFIG_LCZ_LWM2M_GATEWAY_PREFIX_MAX_STR_SIZE) {
			options[0].len = CONFIG_LCZ_LWM2M_GATEWAY_PREFIX_MAX_STR_SIZE;
		}
		memset(prefix, 0, sizeof(prefix));
		memcpy(prefix, options[0].value, options[0].len);

		i = lcz_lwm2m_gw_obj_lookup_path(prefix);
		if (i >= 0) {
			/* Foward the message to the sensor */
			forward_prefixed_message(i, request);

			/* Do nothing else with the message in this context */
			ret = LWM2M_COAP_RESP_NONE;
		}
	}

	/* Anything else coming from a sensor should be returned to the server */
	else if (pctx != NULL) {
		/* Forward message to the server */
		forward_sensor_reply(pctx, request);

		/* Do nothing else with the message in this context */
		ret = LWM2M_COAP_RESP_NONE;
	}

	/* Else, check to see if this is a reply from the server to a sensor */
	else {
		struct coap_pending *pending;
		struct coap_reply *reply;

		for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS; i++) {
			if ((proxy_ctx[i].flags & CTX_FLAG_ACTIVE) != 0) {
				pending =
					coap_pending_received(request, proxy_ctx[i].pendings,
							      CONFIG_LCZ_LWM2M_ENGINE_MAX_PENDING);
				if (pending != NULL) {
					break;
				}
			}
		}

		if (pending != NULL && i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS) {
			/* Remove the pending tracking */
			coap_pending_clear(pending);

			/* Also check to see if this is a reply we're tracking */
			reply = coap_response_received(request, NULL, proxy_ctx[i].replies,
						       CONFIG_LCZ_LWM2M_ENGINE_MAX_REPLIES);
			if (reply != NULL) {
				coap_reply_clear(reply);
			}

			/* Foward the message to the sensor */
			forward_reply_message(&(proxy_ctx[i]), request);

			/* Do nothing else with the message this context */
			ret = LWM2M_COAP_RESP_NONE;
		}
	}

	/* Release the mutex */
	k_mutex_unlock(&proxy_mutex);

	return ret;
}

/** @brief Start a new proxy context
 *
 * @param[in] ctx_idx Index of the context to start. Must already be free.
 * @param[in] dev_idx Device with which to establish the connection
 * @param[in] flags Any option flags to apply to the new context
 *
 * @returns 0 on success or another value on failure.
 */
static int start_context(int ctx_idx, int dev_idx, uint8_t flags)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;
	int ret;

	/* Get the device data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(dev_idx);

	/* Unlikely, but fail if the device data hasn't been created yet */
	if (pdev == NULL) {
		return -ENODATA;
	}

	/* Reset everything in the context structure */
	memset(&(proxy_ctx[ctx_idx]), 0, sizeof(proxy_ctx[0]));

	/* Initialize the delayed work */
	k_work_init_delayable(&(proxy_ctx[ctx_idx].conn_timeout_work), conn_timeout_work_handler);

	/* Mark the context as active */
	proxy_ctx[ctx_idx].flags = CTX_FLAG_ACTIVE | flags;
	proxy_ctx[ctx_idx].dev_idx = dev_idx;

	/* Start the transport */
	proxy_ctx[ctx_idx].ctx.transport_name = "ble_central";
	proxy_ctx[ctx_idx].ctx.sock_fd = INVALID_SOCKET;
	proxy_ctx[ctx_idx].ctx.fault_cb = transport_fault_cb;
	proxy_ctx[ctx_idx].ctx.coap_msg_cb = transport_coap_msg_cb;
	proxy_ctx[ctx_idx].ctx.observe_cb = NULL;
	proxy_ctx[ctx_idx].coded_phy = pdev->coded_phy;

	LOG_INF("Starting proxy context %d (dev %d) for %s", ctx_idx, dev_idx,
		lcz_lwm2m_gw_obj_get_addr_string(dev_idx));

	ret = lwm2m_engine_start(&(proxy_ctx[ctx_idx].ctx));
	if (ret < 0) {
		LOG_ERR("Cannot initialize LwM2M proxy context: %d", ret);
		lwm2m_engine_context_close(&(proxy_ctx[ctx_idx].ctx));
	} else {
		/* Start the connection timer */
		reset_conn_timer(&(proxy_ctx[ctx_idx]));
	}

	return ret;
}

/** @brief Add a CoAP packet to a queue
 *
 * @param[in] queue Queue to which the CoAP packet should be added
 * @param[in] pkt The packet to add to the queue
 *
 * @returns 0 on success or another value on failure.
 */
static int add_to_queue(struct k_fifo *queue, struct coap_packet *pkt)
{
	struct coap_queue_entry_t *item = NULL;
	int rc = -EINVAL;

	if (pkt != NULL) {
		item = k_malloc(sizeof(struct coap_queue_entry_t) - 1 + pkt->offset);
		if (item == NULL) {
			rc = -ENOMEM;
		} else {
			/* Copy the packet */
			memcpy(&(item->pkt), pkt, sizeof(struct coap_packet));

			/* Copy the data */
			memcpy(item->pkt_data, pkt->data, pkt->offset);

			/* Update the packet pointer */
			item->pkt.data = item->pkt_data;

			k_fifo_put(queue, item);
			rc = 0;
		}
	}

	return rc;
}

/** @brief Delayed work handler for proxy connection timeout
 *
 * When this function is called, the connection timeout for a proxy connection
 * has expired. If the connection is active, it will be closed.
 *
 * @param[in] work Pointer to work item
 */
static void conn_timeout_work_handler(struct k_work *work)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx =
		CONTAINER_OF(work, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, conn_timeout_work);
	int ctx_idx = (pctx - proxy_ctx) / sizeof(proxy_ctx[0]);

	LOG_INF("Proxy context %d timeout", ctx_idx);

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&proxy_mutex, K_FOREVER);

	/* If the connection is active, close it */
	if ((pctx->flags & CTX_FLAG_ACTIVE) != 0) {
		/* Close the context and transport */
		lwm2m_engine_context_close(&(pctx->ctx));

		/*
		 * Engine context close will call the BLE central transport close function,
		 * which will call our lcz_lwm2m_gateway_proxy_close() function to release
		 * the proxy context data structure.
	 	 */
	}

	/* Release the mutex */
	k_mutex_unlock(&proxy_mutex);
}

/** @brief LwM2M context fault callback
 *
 * When a transport error occurs with a proxy LwM2M connection, this function
 * is called to close the connection.
 *
 * @param[in] ctx LwM2M connection context
 * @param[in] error Code for error that occurred
 */
static void transport_fault_cb(struct lwm2m_ctx *ctx, int error)
{
	if (error) {
		LOG_ERR("LwM2M transport error: %d", error);
	}

	/* Close the context and transport */
	lwm2m_engine_context_close(ctx);

	/*
	 * Engine context close will call the BLE central transport close function,
	 * which will call our lcz_lwm2m_gateway_proxy_close() function to release
	 * the proxy context data structure.
 	 */
}

/** @brief Convert a device index into a proxy connection context index
 *
 * @param[in] dev_idx Device index to convert
 *
 * @returns If a proxy connection context exists for the device, the context
 * index is returned. Else, -1 is returned.
 */
static int dev_idx_to_ctx_idx(int dev_idx)
{
	int ctx_idx;

	for (ctx_idx = 0; ctx_idx < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS; ctx_idx++) {
		if ((proxy_ctx[ctx_idx].flags & CTX_FLAG_ACTIVE) != 0 &&
		    proxy_ctx[ctx_idx].dev_idx == dev_idx) {
			break;
		}
	}

	if (ctx_idx < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS) {
		return ctx_idx;
	} else {
		return CTX_IDX_INVALID;
	}
}

/** @brief Callback when a gateway object is deleted
 *
 * The callback is called when a gateway device object (object 25 instance) is deleted.
 * The deletion is either a result of a registration lifetime timeout or the server
 * determining that the gateway should not be communicating with the end device. The
 * reason doesn't matter here. We use this callback to close any open connection with the
 * device and free our associated data.
 *
 * @param[in] dev_idx Index of the device that is being deleted
 * @param[in] data_ptr Our private data pointer associated with the device
 */
void obj_deleted(int dev_idx, void *data_ptr)
{
	int ctx_idx;

	/* Close any context associated with this device */
	ctx_idx = dev_idx_to_ctx_idx(dev_idx);
	if (ctx_idx != CTX_IDX_INVALID) {
		lwm2m_engine_context_close(&(proxy_ctx[ctx_idx].ctx));

		/*
		 * Engine context close will call the BLE central transport close function,
		 * which will call our lcz_lwm2m_gateway_proxy_close() function to release
		 * the proxy context data structure.
	 	 */
	}

	/* Free our data */
	if (data_ptr != NULL) {
		k_free(data_ptr);
	}
}

SYS_INIT(lcz_lwm2m_gateway_proxy_init, APPLICATION, CONFIG_LCZ_LWM2M_GATEWAY_PROXY_INIT_PRIORITY);
/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
static int lcz_lwm2m_gateway_proxy_init(const struct device *device)
{
	ARG_UNUSED(device);
	int i;

	/* Reset the proxy structures */
	for (i = 0; i < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_NUM_CONTEXTS; i++) {
		/* Reset the entire structure */
		memset(&(proxy_ctx[i]), 0, sizeof(proxy_ctx[0]));

		/* Block the context from being used until we're started */
		proxy_ctx[i].flags = CTX_FLAG_STOPPED;
	}

	/* Register a callback with the server client */
	(void)lcz_lwm2m_client_register_event_callback(&lwm2m_event_agent);

	/* Register a callback for when devices are deleted */
	lcz_lwm2m_gw_obj_set_dm_delete_cb(obj_deleted);

#if defined(CONFIG_LCZ_LWM2M_GATEWAY_PROXY_COAP_FILE)
	/* Initialize the proxy file cache */
	lcz_lwm2m_gateway_file_proxy_init();
#endif

	return 0;
}