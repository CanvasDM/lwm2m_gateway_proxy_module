/**
 * @file lcz_lwm2m_transport_ble_central.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_lwm2m_ble_central, CONFIG_LCZ_LWM2M_CLIENT_LOG_LEVEL);

#include <fcntl.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <init.h>
#include <sys/printk.h>
#include <posix/sys/eventfd.h>
#include <bluetooth/conn.h>
#include <bluetooth/gatt.h>
#include <bluetooth/gatt_dm.h>
#include <bluetooth/services/dfu_smp.h>
#include <mgmt/mgmt.h>
#include <mgmt/mcumgr/smp_bt.h>
#include <zcbor_common.h>
#include <zcbor_encode.h>
#include <zcbor_decode.h>
#include <lcz_lwm2m.h>

#include "lcz_bluetooth.h"
#include "lcz_lwm2m_client.h"
#include "lcz_lwm2m_gateway_obj.h"
#include "lcz_lwm2m_gateway_proxy_scan.h"
#include "lcz_lwm2m_gateway_proxy.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define EVENTFD_DATA_READY 1

/* Return values from the transport recv function */
#define RECV_ERR -1
#define RECV_AGAIN 0
#define RECV_STOP 1

#define INVALID_SOCKET -1

struct queue_entry_t {
	void *fifo_reserved;
	size_t length;
	uint8_t data[1];
};

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_lwm2m_transport_ble_central_init(const struct device *dev);

static int lwm2m_transport_ble_central_start(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_ble_central_send(struct lwm2m_ctx *client_ctx, const uint8_t *data,
					    uint32_t datalen);
static int lwm2m_transport_ble_central_recv(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_ble_central_close(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_ble_central_is_connected(struct lwm2m_ctx *client_ctx);
static void lwm2m_transport_ble_central_tx_pending(struct lwm2m_ctx *client_ctx, bool pending);
static char *lwm2m_transport_ble_central_print_addr(struct lwm2m_ctx *client_ctx,
						    const struct sockaddr *addr);

static void smp_client_send_work_function(struct k_work *w);
static void smp_client_resp_handler(struct bt_dfu_smp *dfu_smp);
static void dfu_smp_on_error(struct bt_dfu_smp *dfu_smp, int err);

static int add_to_queue(struct k_fifo *queue, uint8_t *data, size_t len);

static void exchange_func(struct bt_conn *conn, uint8_t err,
			  struct bt_gatt_exchange_params *params);

static void bt_connected(struct bt_conn *conn, uint8_t conn_err);
static void bt_disconnected(struct bt_conn *conn, uint8_t reason);
static bool bt_param_req(struct bt_conn *conn, struct bt_le_conn_param *param);
static void bt_security_changed(struct bt_conn *conn, bt_security_t level,
				enum bt_security_err err);

static void discovery_completed_cb(struct bt_gatt_dm *dm, void *context);
static void discovery_service_not_found_cb(struct bt_conn *conn, void *context);
static void discovery_error_found_cb(struct bt_conn *conn, int err, void *context);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static const struct lwm2m_transport_procedure ble_central_transport = {
	lwm2m_transport_ble_central_start,	  lwm2m_transport_ble_central_send,
	lwm2m_transport_ble_central_recv,	  lwm2m_transport_ble_central_close,
	lwm2m_transport_ble_central_is_connected, lwm2m_transport_ble_central_tx_pending,
	lwm2m_transport_ble_central_print_addr,
};

/** @brief BT connection callbacks */
static struct bt_conn_cb conn_callbacks = {
	.connected = bt_connected,
	.disconnected = bt_disconnected,
	.le_param_req = bt_param_req,
	.security_changed = bt_security_changed,
};

/** @brief Discovery service callbacks */
static const struct bt_gatt_dm_cb discovery_cb = {
	.completed = discovery_completed_cb,
	.service_not_found = discovery_service_not_found_cb,
	.error_found = discovery_error_found_cb,
};

/** @brief DFU client initialization parameters */
static const struct bt_dfu_smp_init_params dfu_init_params = {
	.error_cb = dfu_smp_on_error,
	.notif_cb = smp_client_resp_handler,
};

static const struct bt_gatt_exchange_params exchange_params = { .func = exchange_func };

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
/** @brief Close an eventfd socket
 *
 * Without CONFIG_POSIX_API, there is no API to close an eventfd socket.
 * This is what close() would do if it worked.
 *
 * @param[in] fd Eventfd to close
 */
static void eventfd_close(int fd)
{
	const struct fd_op_vtable *efd_vtable;
	struct k_mutex *lock;
	void *obj;

	obj = z_get_fd_obj_and_vtable(fd, &efd_vtable, &lock);
	if (obj != NULL && lock != NULL) {
		(void)k_mutex_lock(lock, K_FOREVER);
		efd_vtable->close(obj);
		z_free_fd(fd);
		k_mutex_unlock(lock);
	}
}

/** @brief Start a BLE central LwM2M transport
 *
 * This function initializes a BLE central LwM2M connection and then
 * attempts to create a BLE connection with the peripheral referenced to
 * by pctx->dev_idx.
 *
 * @param[in] client_ctx LwM2M context being started
 *
 * @returns 0 on success, <0 on error
 */
static int lwm2m_transport_ble_central_start(struct lwm2m_ctx *client_ctx)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx =
		CONTAINER_OF(client_ctx, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, ctx);
	struct bt_le_conn_param *param = BT_LE_CONN_PARAM_DEFAULT;
	int err;

	/* Initialize the work item */
	k_work_init(&(pctx->tunnel_tx_work), smp_client_send_work_function);

	/* Initialize the mutex */
	k_mutex_init(&(pctx->lock));

	/* Initialize our receive and transmit queues */
	k_fifo_init(&(pctx->rx_queue));
	k_fifo_init(&(pctx->tx_queue));

	/* Initialize the SMP Client */
	memset(&(pctx->smp_client), 0, sizeof(pctx->smp_client));
	bt_dfu_smp_init(&(pctx->smp_client), &dfu_init_params);

	/* Stop scanning */
	lcz_lwm2m_gateway_proxy_scan_pause();

	/* Open the BLE connection */
	err = bt_conn_le_create(lcz_lwm2m_gw_obj_get_address(pctx->dev_idx), BT_CONN_LE_CREATE_CONN,
				param, &(pctx->active_conn));
	if (err) {
		LOG_ERR("Create connection failed: %d", err);
		pctx->active_conn = NULL;

		/* Resume scanning */
		lcz_lwm2m_gateway_proxy_scan_resume();
		return err;
	} else {
		/* Create the eventfd file descriptor */
		client_ctx->sock_fd = eventfd(0, EFD_NONBLOCK);
		if (client_ctx->sock_fd < 0) {
			LOG_ERR("Failed to create eventfd socket: %d", client_ctx->sock_fd);
			bt_conn_disconnect(pctx->active_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
			bt_conn_unref(pctx->active_conn);
			pctx->active_conn = NULL;
			return client_ctx->sock_fd;
		} else {
			return 0;
		}
	}
}

/** @brief Send data for a BLE central LwM2M context
 *
 * The data to be sent is added to the transmit queue for the context. If the tunnel to
 * the peripheral device is available, the transmit work is scheduled.
 *
 * @param[in] client_ctx LwM2M context
 * @param[in] data Pointer to data to send
 * @param[in] datalen Length of data to send
 *
 * @returns 0 on success, <0 on error
 */
static int lwm2m_transport_ble_central_send(struct lwm2m_ctx *client_ctx, const uint8_t *data,
					    uint32_t datalen)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx =
		CONTAINER_OF(client_ctx, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, ctx);
	int rc = 0;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&(pctx->lock), K_FOREVER);

	/* Add the data to our transmit queue */
	rc = add_to_queue(&(pctx->tx_queue), (uint8_t *)data, datalen);

	/* If the tunnel is open and not busy, can send now */
	if (rc == 0 &&
	    (pctx->flags & (CTX_FLAG_CLIENT_TUNNEL_OPEN | CTX_FLAG_CLIENT_TUNNEL_BUSY)) ==
		    CTX_FLAG_CLIENT_TUNNEL_OPEN) {
		k_work_submit(&(pctx->tunnel_tx_work));
	}

	/* Else, wait until the tunnel is open or not busy to send */

	/* Release the mutex lock for our data */
	k_mutex_unlock(&(pctx->lock));

	/* Call the fault callback on error */
	if (rc != 0) {
		if (client_ctx->fault_cb != NULL) {
			client_ctx->fault_cb(&(pctx->ctx), rc);
		}
	}

	return rc;
}

/** @brief Receive data for a LwM2M BLE central context
 *
 * If data is ready to be received for the context, the lwm2m_coap_receive() function
 * will be called with the data.
 *
 * @param[in] client_ctx LwM2M context
 *
 * @returns 0 on success, <0 on error
 */
static int lwm2m_transport_ble_central_recv(struct lwm2m_ctx *client_ctx)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx =
		CONTAINER_OF(client_ctx, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, ctx);
	struct queue_entry_t *item;
	struct sockaddr from_addr;
	eventfd_t event_val;
	int rc = RECV_ERR;

	/* Create an empty address */
	memset(&from_addr, 0, sizeof(from_addr));

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&(pctx->lock), K_FOREVER);

	/* Clear the event FD for now */
	(void)eventfd_read(client_ctx->sock_fd, &event_val);

	/* Don't allow this function to be called again immediately */
	rc = RECV_STOP;

	/* Fetch the packet from the queue */
	item = k_fifo_get(&(pctx->rx_queue), K_NO_WAIT);
	if (item != NULL) {
		/* Send the received packet to the CoAP handler */
		lwm2m_coap_receive(client_ctx, item->data, item->length, &from_addr);
		k_free(item);
	}

	/* If there is still data left in the queue, make the socket readable */
	if (!k_fifo_is_empty(&(pctx->rx_queue))) {
		event_val = EVENTFD_DATA_READY;
		(void)eventfd_write(client_ctx->sock_fd, event_val);

		/* Allow this function to be called again */
		rc = RECV_AGAIN;
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&(pctx->lock));

	return rc;
}

/** @brief Close a BLE central LwM2M context
 *
 * This function performs any cleanup needed for the BLE central transport of a
 * LwM2M context. This includes emptying queues and disconnecting the underlying
 * Bluetooth connection.
 *
 * @param[in] client_ctx LwM2M context to be closed
 *
 * @returns 0 on success, <0 on error
 */
static int lwm2m_transport_ble_central_close(struct lwm2m_ctx *client_ctx)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx =
		CONTAINER_OF(client_ctx, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, ctx);
	struct queue_entry_t *item;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&(pctx->lock), K_FOREVER);

	/* Stop any pending work */
	k_work_cancel(&(pctx->tunnel_tx_work));

	/* Empty the receive queue */
	do {
		item = k_fifo_get(&(pctx->rx_queue), K_NO_WAIT);
		if (item != NULL) {
			k_free(item);
		}
	} while (item != NULL);

	/* Empty the transmit queue */
	do {
		item = k_fifo_get(&(pctx->tx_queue), K_NO_WAIT);
		if (item != NULL) {
			k_free(item);
		}
	} while (item != NULL);

	/* Close the eventfd socket */
	if (client_ctx->sock_fd >= 0) {
		eventfd_close(client_ctx->sock_fd);
		client_ctx->sock_fd = INVALID_SOCKET;
	}

	/* If we still have a BLE connection, close it */
	if (pctx->active_conn != NULL) {
		bt_conn_disconnect(pctx->active_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);

		/* Release our reference to the connection */
		bt_conn_unref(pctx->active_conn);
		pctx->active_conn = NULL;
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&(pctx->lock));

	/* Release the context */
	lcz_lwm2m_gateway_proxy_close(pctx);

	return 0;
}

/** @brief Checks to see if a BLE central LwM2M transport is connected to a peripheral
 *
 * @param[in] client_ctx LwM2M context
 *
 * @returns 1 if connected, 0 if not.
 */
static int lwm2m_transport_ble_central_is_connected(struct lwm2m_ctx *client_ctx)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx =
		CONTAINER_OF(client_ctx, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, ctx);
	int rc = 0;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&(pctx->lock), K_FOREVER);

	/* If the tunnel is open, we're connected */
	if ((pctx->flags & CTX_FLAG_CLIENT_TUNNEL_OPEN) == CTX_FLAG_CLIENT_TUNNEL_OPEN) {
		rc = 1;
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&(pctx->lock));

	return rc;
}

/** @brief Informs the transport that a transmit is pending
 *
 * @param[in] client_ctx LwM2M context
 * @param[in] pending true if a transmit is needed, false if not
 */
static void lwm2m_transport_ble_central_tx_pending(struct lwm2m_ctx *client_ctx, bool pending)
{
	/* Nothing to do here */
}

/** @brief Put the peer address of the transport into a string
 *
 * @param[in] client_ctx LwM2M context
 * @param[in] addr Socket address
 *
 * @returns a pointer to a string representing the peer address
 */
static char *lwm2m_transport_ble_central_print_addr(struct lwm2m_ctx *client_ctx,
						    const struct sockaddr *addr)
{
	ARG_UNUSED(addr);
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx =
		CONTAINER_OF(client_ctx, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, ctx);
	return lcz_lwm2m_gw_obj_get_addr_string(pctx->dev_idx);
}

/** @brief Work handler for transmitting packets over the tunnel
 *
 * This function removes one item from the context's tunnel transmit queue,
 * encodes a CBOR and SMP message to tunnel that data to the peripheral,
 * and sends it.
 *
 * @param[in] w Work item pointer
 */
static void smp_client_send_work_function(struct k_work *w)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx =
		CONTAINER_OF(w, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, tunnel_tx_work);
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;
	zcbor_state_t zs[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];
	struct zcbor_string zstr;
	bool ok;
	int err = 0;
	struct queue_entry_t *item;
	struct lwm2m_gw_smp_buffer smp_buf;
	uint16_t payload_len;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&(pctx->lock), K_FOREVER);

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);

	/* Remove the first item from the transmit queue */
	item = k_fifo_get(&(pctx->tx_queue), K_NO_WAIT);
	if (item != NULL) {
		/* Build the CBOR message */
		zcbor_new_state(zs, sizeof(zs) / sizeof(zs[0]), smp_buf.payload,
				sizeof(smp_buf.payload), 1);
		ok = zcbor_map_start_encode(zs, 1);
		if (ok) {
			zstr.len = strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID);
			zstr.value = LCZ_COAP_CBOR_KEY_TUNNEL_ID;
			ok = zcbor_tstr_encode(zs, &zstr);
		}
		if (ok) {
			ok = zcbor_uint32_encode(zs, &(pdev->tunnel_id));
		}
		if (ok) {
			zstr.len = strlen(LCZ_COAP_CBOR_KEY_DATA);
			zstr.value = LCZ_COAP_CBOR_KEY_DATA;
			ok = zcbor_tstr_encode(zs, &zstr);
		}
		if (ok) {
			zstr.len = item->length;
			zstr.value = item->data;
			ok = zcbor_bstr_encode(zs, &zstr);
		}
		if (ok) {
			ok = zcbor_map_end_encode(zs, 1);
		}

		payload_len = (size_t)(zs[0].payload - smp_buf.payload);

		/* Fill in SMP message header */
		smp_buf.header.op = MGMT_OP_WRITE;
		smp_buf.header.flags = 0;
		smp_buf.header.len_h8 = (uint8_t)((payload_len >> 8) & 0xFF);
		smp_buf.header.len_l8 = (uint8_t)((payload_len >> 0) & 0xFF);
		smp_buf.header.group_h8 =
			(uint8_t)((CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 8) & 0xFF);
		smp_buf.header.group_l8 =
			(uint8_t)((CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 0) & 0xFF);
		smp_buf.header.seq = 0;
		smp_buf.header.id = LCZ_COAP_MGMT_ID_TUNNEL_DATA;

		if (ok) {
			err = bt_dfu_smp_command(&(pctx->smp_client), smp_client_resp_handler,
						 sizeof(smp_buf.header) + payload_len, &smp_buf);
			if (err == 0) {
				pctx->flags |= CTX_FLAG_CLIENT_TUNNEL_BUSY;
			} else {
				LOG_ERR("Failed to send tunnel data message: %d", err);
			}
		} else {
			LOG_ERR("Failed to encode tunnel data message");
			err = -ENOMEM;
		}

		/* Free the queue item memory */
		k_free(item);
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&(pctx->lock));

	if (err) {
		if (pctx->ctx.fault_cb != NULL) {
			pctx->ctx.fault_cb(&(pctx->ctx), err);
		}
	}
}

/** @brief Send an Open Tunnel message to the peripheral
 *
 * This function builds the CBOR and SMP message for the Open Tunnel message and
 * sends it to the peripheral.
 *
 * @param[in] pctx Proxy context for which the message should be sent
 */
static void smp_client_send_open_tunnel(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;
	zcbor_state_t zs[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];
	struct zcbor_string zstr;
	bool ok;
	int err = 0;
	struct lwm2m_gw_smp_buffer smp_buf;
	uint16_t payload_len;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&(pctx->lock), K_FOREVER);

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);

	/* Build the CBOR message */
	zcbor_new_state(zs, sizeof(zs) / sizeof(zs[0]), smp_buf.payload, sizeof(smp_buf.payload),
			1);
	ok = zcbor_map_start_encode(zs, 1);
	if (ok) {
		zstr.len = strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID);
		zstr.value = LCZ_COAP_CBOR_KEY_TUNNEL_ID;
		ok = zcbor_tstr_encode(zs, &zstr);
	}
	if (ok) {
		ok = zcbor_uint32_encode(zs, &(pdev->tunnel_id));
	}
	if (ok) {
		ok = zcbor_map_end_encode(zs, 1);
	}

	payload_len = (size_t)(zs[0].payload - smp_buf.payload);

	/* Fill in SMP message header */
	smp_buf.header.op = MGMT_OP_WRITE;
	smp_buf.header.flags = 0;
	smp_buf.header.len_h8 = (uint8_t)((payload_len >> 8) & 0xFF);
	smp_buf.header.len_l8 = (uint8_t)((payload_len >> 0) & 0xFF);
	smp_buf.header.group_h8 = (uint8_t)((CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 8) & 0xFF);
	smp_buf.header.group_l8 = (uint8_t)((CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 0) & 0xFF);
	smp_buf.header.seq = 0;
	smp_buf.header.id = LCZ_COAP_MGMT_ID_OPEN_TUNNEL;

	if (ok) {
		err = bt_dfu_smp_command(&(pctx->smp_client), smp_client_resp_handler,
					 sizeof(smp_buf.header) + payload_len, &smp_buf);
		if (err == 0) {
			pctx->flags |= CTX_FLAG_CLIENT_TUNNEL_BUSY;
		} else {
			LOG_ERR("Failed to send open tunnel message: %d", err);
		}
	} else {
		LOG_ERR("Failed to encode open tunnel message");
		err = -ENOMEM;
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&(pctx->lock));

	if (err != 0) {
		if (pctx->ctx.fault_cb != NULL) {
			pctx->ctx.fault_cb(&(pctx->ctx), err);
		}
	}
}

/** @brief Handler for the Open Tunnel response message from the peripheral
 *
 * @param[in] pctx Proxy context pointer for the transport connection
 * @param[in] zsd ZCBOR state for decoding the Open Tunnel response message
 *
 * @returns 0 on success, <0 on error.
 */
static int handle_open_tunnel_resp(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, zcbor_state_t *zsd)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;
	uint32_t tunnel_id = 0;
	struct zcbor_string key;
	int rc = 0;

	/* Decode the CBOR payload */
	if (zcbor_map_start_decode(zsd) == false || zcbor_tstr_decode(zsd, &key) == false ||
	    key.len != strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID) ||
	    strncmp(key.value, LCZ_COAP_CBOR_KEY_TUNNEL_ID, strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID)) !=
		    0 ||
	    zcbor_uint32_decode(zsd, &tunnel_id) == false || zcbor_map_end_decode(zsd) == false) {
		LOG_ERR("handle_open_tunnel_resp: decode failed");
		rc = -EINVAL;
	}

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);

	/* Validate the message */
	if (rc == 0) {
		if (pdev == NULL || tunnel_id != pdev->tunnel_id) {
			/* Block this device for a period of time */
			lcz_lwm2m_gw_obj_add_blocklist(
				pctx->dev_idx,
				CONFIG_LCZ_LWM2M_GATEWAY_PROXY_BLOCKLIST_TIME_SECONDS);

			/*
			 * Wrong tunnel ID. Returning an error here will
			 * cause the connection to be closed.
			 */
			LOG_WRN("handle_open_tunnel_resp: peripheral returned tunnel id %d",
				tunnel_id);
			rc = -EINVAL;
		}
	}

	return rc;
}

/** @brief Handler for the Tunnel Data message from the peripheral
 *
 * @param[in] pctx Proxy context pointer for the transport connection
 * @param[in] zsd ZCBOR state for decoding the Tunnel Data message
 *
 * @returns 0 on success, <0 on error.
 */
static int handle_tunnel_data(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, zcbor_state_t *zsd)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;
	uint32_t tunnel_id;
	struct zcbor_string key;
	struct zcbor_string value;
	eventfd_t event_val;
	int rc = 0;

	if (zcbor_map_start_decode(zsd) == false || zcbor_tstr_decode(zsd, &key) == false ||
	    key.len != strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID) ||
	    strncmp(key.value, LCZ_COAP_CBOR_KEY_TUNNEL_ID, strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID)) !=
		    0 ||
	    zcbor_uint32_decode(zsd, &tunnel_id) == false ||
	    zcbor_tstr_decode(zsd, &key) == false || key.len != strlen(LCZ_COAP_CBOR_KEY_DATA) ||
	    strncmp(key.value, LCZ_COAP_CBOR_KEY_DATA, strlen(LCZ_COAP_CBOR_KEY_DATA)) != 0 ||
	    zcbor_bstr_decode(zsd, &value) == false || value.len == 0 ||
	    zcbor_map_end_decode(zsd) == false) {
		LOG_ERR("handle_tunnel_data: decode failed");
		rc = -EINVAL;
	}

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);

	/* If message is valid, handle it */
	if (rc == 0 && pdev != NULL && tunnel_id == pdev->tunnel_id) {
		/* Add it to our RX queue */
		if (add_to_queue(&(pctx->rx_queue), (uint8_t *)value.value, value.len) == 0) {
			/* Signal the event FD that data is ready to be read */
			event_val = EVENTFD_DATA_READY;
			(void)eventfd_write(pctx->ctx.sock_fd, event_val);
		}
	} else if (rc == 0) {
		LOG_ERR("handle_tunnel_data: peripheral returned tunnel id %d", tunnel_id);
		rc = -EINVAL;
	}

	return rc;
}

/** @brief Handler for the Tunnel Data response message from the peripheral
 *
 * @param[in] pctx Proxy context pointer for the transport connection
 * @param[in] zsd ZCBOR state for decoding the Tunnel Data response message
 *
 * @returns 0 on success, <0 on error.
 */
static int handle_tunnel_data_resp(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, zcbor_state_t *zsd)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;
	uint32_t tunnel_id = 0;
	struct zcbor_string key;
	int rc = 0;

	/* Decode the CBOR payload */
	if (zcbor_map_start_decode(zsd) == false || zcbor_tstr_decode(zsd, &key) == false ||
	    key.len != strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID) ||
	    strncmp(key.value, LCZ_COAP_CBOR_KEY_TUNNEL_ID, strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID)) !=
		    0 ||
	    zcbor_uint32_decode(zsd, &tunnel_id) == false || zcbor_map_end_decode(zsd) == false) {
		LOG_ERR("handle_tunnel_data_resp: decode failed");
		rc = -EINVAL;
	}

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);

	/* Validate the message */
	if (rc == 0) {
		if (pdev == NULL || tunnel_id != pdev->tunnel_id) {
			/*
			 * Wrong tunnel ID. Returning an error here will
			 * cause the connection to be closed.
			 */
			LOG_ERR("handle_tunnel_data_resp: peripheral returned tunnel id %d",
				tunnel_id);
			rc = -EINVAL;
		}
	}

	return rc;
}

/** @brief Handler for the Close Tunnel response message from the peripheral
 *
 * @param[in] pctx Proxy context pointer for the transport connection
 * @param[in] zsd ZCBOR state for decoding the Close Tunnel response message
 *
 * @returns 0 on success, <0 on error.
 */
static int handle_close_tunnel_resp(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, zcbor_state_t *zsd)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;
	uint32_t tunnel_id = 0;
	struct zcbor_string key;
	int rc = 0;

	/* Decode the CBOR payload */
	if (zcbor_map_start_decode(zsd) == false || zcbor_tstr_decode(zsd, &key) == false ||
	    key.len != strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID) ||
	    strncmp(key.value, LCZ_COAP_CBOR_KEY_TUNNEL_ID, strlen(LCZ_COAP_CBOR_KEY_TUNNEL_ID)) !=
		    0 ||
	    zcbor_uint32_decode(zsd, &tunnel_id) == false || zcbor_map_end_decode(zsd) == false) {
		LOG_ERR("handle_close_tunnel_resp: decode failed");
		rc = -EINVAL;
	}

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);

	/* Validate the message */
	if (rc == 0) {
		if (pdev == NULL || tunnel_id != pdev->tunnel_id) {
			/*
			 * Wrong tunnel ID. Returning an error here will
			 * cause the connection to be closed.
			 */
			LOG_ERR("handle_tunnel_data_resp: peripheral returned tunnel id %d",
				tunnel_id);
			rc = -EINVAL;
		}
	}

	return rc;
}

/** @brief Handler for a received CoAP tunnel SMP message from the peripheral
 *
 * @param[in] pctx Proxy context pointer for the transport connection
 *
 * @returns 0 on success, <0 on error.
 */
static int handle_smp_message(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx)
{
	uint16_t payload_len = ((uint16_t)pctx->smp_rsp_buff.header.len_h8) << 8 |
			       pctx->smp_rsp_buff.header.len_l8;
	int err = -EINVAL;
	zcbor_state_t states[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];

	/* Initialize the CBOR reader */
	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), pctx->smp_rsp_buff.payload,
			payload_len, 1);

	if (pctx->smp_rsp_buff.header.op == MGMT_OP_WRITE_RSP) {
		switch (pctx->smp_rsp_buff.header.id) {
		case LCZ_COAP_MGMT_ID_OPEN_TUNNEL:
			err = handle_open_tunnel_resp(pctx, states);
			break;
		case LCZ_COAP_MGMT_ID_TUNNEL_DATA:
			err = handle_tunnel_data_resp(pctx, states);
			break;
		case LCZ_COAP_MGMT_ID_CLOSE_TUNNEL:
			err = handle_close_tunnel_resp(pctx, states);
			break;
		default:
			LOG_ERR("Unknown SMP write response ID %d", pctx->smp_rsp_buff.header.id);
			break;
		}
	} else if (pctx->smp_rsp_buff.header.op == LCZ_COAP_MGMT_OP_NOTIFY) {
		switch (pctx->smp_rsp_buff.header.id) {
		case LCZ_COAP_MGMT_ID_TUNNEL_DATA:
			err = handle_tunnel_data(pctx, states);
			break;
		default:
			LOG_ERR("Unknown SMP notify ID %d", pctx->smp_rsp_buff.header.id);
			break;
		}
	}

	return err;
}

/** @brief Handler for a received SMP message from the peripheral
 *
 * @param[in] dfu_smp DFU SMP client structure pointer
 */
static void smp_client_resp_handler(struct bt_dfu_smp *dfu_smp)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx =
		CONTAINER_OF(dfu_smp, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, smp_client);
	uint8_t *p_outdata = (uint8_t *)(&(pctx->smp_rsp_buff));
	const struct bt_dfu_smp_rsp_state *rsp_state;
	int err = 0;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&(pctx->lock), K_FOREVER);

	/* Get the current response state */
	rsp_state = bt_dfu_smp_rsp_state(dfu_smp);

	/* Copy the new data in our response buffer */
	if (rsp_state->offset + rsp_state->chunk_size > sizeof(pctx->smp_rsp_buff)) {
		LOG_ERR("Response size buffer overflow");
		err = -ENOMEM;
	} else {
		p_outdata += rsp_state->offset;
		memcpy(p_outdata, rsp_state->data, rsp_state->chunk_size);
	}

	/* Check to see if that was the end of the message */
	if (err == 0) {
		if (!bt_dfu_smp_rsp_total_check(dfu_smp)) {
			/* This is not an error specifically. We just need to wait for more data. */
			err = -EAGAIN;
		}
	}

	/* Verify the group ID in the message */
	if (err == 0) {
		uint16_t group = ((uint16_t)pctx->smp_rsp_buff.header.group_h8) << 8 |
				 pctx->smp_rsp_buff.header.group_l8;
		if (group != CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP) {
			LOG_ERR("SMP response has wrong group");
			err = -EINVAL;
		}
	}

	/* Handle the write response */
	if (err == 0 && pctx->smp_rsp_buff.header.op == MGMT_OP_WRITE_RSP) {
		/* Process the recevied message */
		err = handle_smp_message(pctx);

		/* Our SMP command is complete. Client tunnel is no longer busy. */
		pctx->flags &= ~CTX_FLAG_CLIENT_TUNNEL_BUSY;

		/* Check to see if we have more data to send */
		if (!k_fifo_is_empty(&(pctx->tx_queue))) {
			k_work_submit(&(pctx->tunnel_tx_work));
		}
	}

	/* Handle the notification */
	else if (err == 0 && pctx->smp_rsp_buff.header.op == LCZ_COAP_MGMT_OP_NOTIFY) {
		/* Process the recevied message */
		err = handle_smp_message(pctx);
	}

	/* Any other operations are errors */
	else if (err == 0) {
		LOG_ERR("Invalid SMP operation %d", pctx->smp_rsp_buff.header.op);
		err = -EINVAL;
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&(pctx->lock));

	/* Handle any errors from above */
	if (err != 0 && err != -EAGAIN) {
		if (pctx->ctx.fault_cb != NULL) {
			pctx->ctx.fault_cb(&(pctx->ctx), err);
		}
	}
}

/** @brief Error callback for DFU SMP client
 *
 * Called when any error happens with the DFU SMP client. This function
 * will call the LwM2M transport fault callback, which will in turn close
 * the connection.
 *
 * @param[in] dfu_smp DFU SMP client structure pointer
 * @param[in] err Error that occurred
 */
static void dfu_smp_on_error(struct bt_dfu_smp *dfu_smp, int err)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx =
		CONTAINER_OF(dfu_smp, LCZ_LWM2M_GATEWAY_PROXY_CTX_T, smp_client);
	LOG_ERR("DFU SMP generic error: %d", err);
	if (pctx->ctx.fault_cb != NULL) {
		pctx->ctx.fault_cb(&(pctx->ctx), err);
	}
}

/** @brief Add a message to a queue
 *
 * @param[in] queue Queue to which the message should be added
 * @param[in] data Pointer to data to add to the queue
 * @param[in] len Length of data pointed to by data
 *
 * @returns 0 on success, <0 on error.
 */
static int add_to_queue(struct k_fifo *queue, uint8_t *data, size_t len)
{
	struct queue_entry_t *item = NULL;
	int rc = -EINVAL;

	if (data != NULL && len > 0) {
		item = k_malloc(sizeof(struct queue_entry_t) - 1 + len);
		if (item == NULL) {
			rc = -ENOMEM;
		} else {
			item->length = len;
			memcpy(item->data, data, len);
			k_fifo_put(queue, item);
			rc = 0;
		}
	}

	return rc;
}

/** @brief Called when the BLE MTU exchange is complete
 *
 * @param[in] conn Bluetooth connection handle
 * @param[in] err Error code for MTU exchange
 * @param[in] params Resulting MTU exchange parameters
 */
static void exchange_func(struct bt_conn *conn, uint8_t err, struct bt_gatt_exchange_params *params)
{
	if (err != 0) {
		LOG_ERR("MTU exchange failed: %d", err);
	}
}

/** @brief Bluetooth connection callback
 *
 * Called whenever a Bluetooth connection has been established or has failed to be
 * established.
 *
 * @param[in] conn Bluetooth connection handle
 * @param[in] conn_err Error code for connection process
 */
static void bt_connected(struct bt_conn *conn, uint8_t conn_err)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx;
	int err = 0;

	/* Look up our context based on the connection */
	pctx = lcz_lwm2m_gateway_proxy_conn_to_context(conn);
	if (conn_err != 0 && pctx != NULL) {
		LOG_ERR("Failed to connect: %u", conn_err);

		/* Release our reference to the connection */
		bt_conn_unref(conn);
		pctx->active_conn = NULL;

		if (pctx->ctx.fault_cb != NULL) {
			pctx->ctx.fault_cb(&(pctx->ctx), conn_err);
		}

		/* Restart scanning */
		lcz_lwm2m_gateway_proxy_scan_resume();
	} else if (pctx != NULL) {
		/* Restart scanning */
		lcz_lwm2m_gateway_proxy_scan_resume();

		/* Enable security on the connection */
		err = bt_conn_set_security(conn, BT_SECURITY_L2);
		if (err) {
			LOG_ERR("Failed to set security: %d", err);
			if (pctx->ctx.fault_cb != NULL) {
				pctx->ctx.fault_cb(&(pctx->ctx), err);
			}
		}

		/* Request the data length update */
		if (err == 0) {
			err = bt_conn_le_data_len_update(conn, BT_LE_DATA_LEN_PARAM_MAX);
			if (err) {
				LOG_ERR("Data length update failed: %d", err);
				if (pctx->ctx.fault_cb != NULL) {
					pctx->ctx.fault_cb(&(pctx->ctx), err);
				}
			}
		}

		/* Exchange MTU sizes */
		if (err == 0) {
			err = bt_gatt_exchange_mtu(
				conn, (struct bt_gatt_exchange_params *)&exchange_params);
			if (err) {
				LOG_ERR("MTU exchange failed: %d", err);
				if (pctx->ctx.fault_cb != NULL) {
					pctx->ctx.fault_cb(&(pctx->ctx), err);
				}
			}
		}

		/* Start discovery of the SMP service */
		if (err == 0) {
			err = bt_gatt_dm_start(conn, BT_UUID_DFU_SMP_SERVICE, &discovery_cb, pctx);
			if (err) {
				LOG_ERR("Could not start discovery: %d", err);
				if (pctx->ctx.fault_cb != NULL) {
					pctx->ctx.fault_cb(&(pctx->ctx), err);
				}
			}
		}
	}
}

/** @brief Bluetooth disconnect callback
 *
 * This function is called when a Bluetooth connection has ended.
 *
 * @param[in] conn Bluetooth connection handle
 * @param[in] reason Reason for the disconnection
 */
static void bt_disconnected(struct bt_conn *conn, uint8_t reason)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx;

	/* Look up our context based on the connection */
	pctx = lcz_lwm2m_gateway_proxy_conn_to_context(conn);

	if (pctx != NULL) {
		/* Restart scanning */
		lcz_lwm2m_gateway_proxy_scan_resume();

		/* Release our reference to the connection */
		bt_conn_unref(conn);
		pctx->active_conn = NULL;

		/* Call the error callback to get the transport closed */
		if (pctx->ctx.fault_cb != NULL) {
			pctx->ctx.fault_cb(&(pctx->ctx), 0);
		}
	}
}

/** @brief Bluetooth callback for connection parameter request
 *
 * @param[in] conn Bluetooth connection handle
 * @param[in] param Proposed connection parameters
 *
 * @returns true if the parameters should be accepted, false if not
 */
static bool bt_param_req(struct bt_conn *conn, struct bt_le_conn_param *param)
{
	/* Minimum is what we want */
	if (param->interval_max > param->interval_min) {
		param->interval_max = param->interval_min;
	}
	param->latency = 0;

	/* Accept the updated parameters */
	return true;
}

/** @brief Bluetooth callback for security change
 *
 * @param[in] conn Bluetooth connection handle
 * @param[in] level New Bluetooth security level
 * @param[in] err Error code (if any) for security change
 */
static void bt_security_changed(struct bt_conn *conn, bt_security_t level, enum bt_security_err err)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx;

	/* Look up our context based on the connection */
	pctx = lcz_lwm2m_gateway_proxy_conn_to_context(conn);
	if (pctx != NULL) {
		/* If the security change was successful, start the tunnel */
		if (level == BT_SECURITY_L2 && err == BT_SECURITY_ERR_SUCCESS) {
			/* Client tunnel is now secure */
			pctx->flags |= CTX_FLAG_CLIENT_SECURE;
			pctx->flags &= ~CTX_FLAG_CLIENT_TUNNEL_BUSY;

			/* If client tunnel is open, send the Open Tunnel command */
			if ((pctx->flags & CTX_FLAG_CLIENT_TUNNEL_OPEN) == CTX_FLAG_CLIENT_TUNNEL_OPEN) {
				smp_client_send_open_tunnel(pctx);
			}
		} else {
			LOG_ERR("bt_security_changed: fail with level %d err %d", level, err);
			if (pctx->ctx.fault_cb != NULL) {
				pctx->ctx.fault_cb(&(pctx->ctx), err);
			}
		}
	}
}

/** @brief Callback for completion of service discovery
 *
 * @param[in] dm Service discovery client structure pointer
 * @param[in] context User-specified custom context data
 */
static void discovery_completed_cb(struct bt_gatt_dm *dm, void *context)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx = (LCZ_LWM2M_GATEWAY_PROXY_CTX_T *)context;
	int err = 0;

	err = bt_dfu_smp_handles_assign(dm, &(pctx->smp_client));
	if (err) {
		LOG_ERR("Could not init DFU SMP client object, error: %d", err);
		if (pctx->ctx.fault_cb != NULL) {
			pctx->ctx.fault_cb(&(pctx->ctx), err);
		}
	} else {
		err = bt_gatt_dm_data_release(dm);
		if (err) {
			LOG_ERR("Could not release the discovery data, error: %d", err);
			if (pctx->ctx.fault_cb != NULL) {
				pctx->ctx.fault_cb(&(pctx->ctx), err);
			}
		}

		/* Client tunnel discovery is complete */
		pctx->flags |= CTX_FLAG_CLIENT_DISCOVER;
		pctx->flags &= ~CTX_FLAG_CLIENT_TUNNEL_BUSY;

		/* If client tunnel is open, send the Open Tunnel command */
		if ((pctx->flags & CTX_FLAG_CLIENT_TUNNEL_OPEN) == CTX_FLAG_CLIENT_TUNNEL_OPEN) {
			smp_client_send_open_tunnel(pctx);
		}
	}
}

/** @brief Callback for completion of service discovery
 *
 * @param[in] conn Bluetooth connection handle
 * @param[in] context User-specified custom context data
 */
static void discovery_service_not_found_cb(struct bt_conn *conn, void *context)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx = (LCZ_LWM2M_GATEWAY_PROXY_CTX_T *)context;

	LOG_ERR("The SMP service could not be found during the discovery");
	if (pctx->ctx.fault_cb != NULL) {
		pctx->ctx.fault_cb(&(pctx->ctx), -ENOENT);
	}
}

/** @brief Callback for service discovery error
 *
 * @param[in] conn Bluetooth connection handle
 * @param[in] err Service discovery error
 * @param[in] context User-specified custom context data
 */
static void discovery_error_found_cb(struct bt_conn *conn, int err, void *context)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx = (LCZ_LWM2M_GATEWAY_PROXY_CTX_T *)context;

	LOG_ERR("The SMP discovery procedure failed with %d", err);
	if (pctx->ctx.fault_cb != NULL) {
		pctx->ctx.fault_cb(&(pctx->ctx), -ENOENT);
	}
}

SYS_INIT(lcz_lwm2m_transport_ble_central_init, APPLICATION, CONFIG_LCZ_LWM2M_CLIENT_INIT_PRIORITY);
/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
static int lcz_lwm2m_transport_ble_central_init(const struct device *dev)
{
	ARG_UNUSED(dev);
	int err;

	/* Register for BT callbacks */
	bt_conn_cb_register(&conn_callbacks);

	/* Register our transport with the LwM2M engine */
	err = lwm2m_transport_register("ble_central",
				       (struct lwm2m_transport_procedure *)&ble_central_transport);
	if (err) {
		LOG_ERR("Failed to register BLE central transport: %d", err);
	}

	return err;
}
