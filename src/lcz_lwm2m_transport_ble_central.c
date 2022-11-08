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
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lcz_lwm2m_ble_central, CONFIG_LCZ_LWM2M_CLIENT_LOG_LEVEL);

#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <zephyr/types.h>
#include <zephyr/init.h>
#include <zephyr/sys/printk.h>
#include <zephyr/posix/sys/eventfd.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <bluetooth/gatt_dm.h>
#include <bluetooth/services/dfu_smp.h>
#include <mgmt/mgmt.h>
#include <zephyr/mgmt/mcumgr/smp_bt.h>
#include <zephyr/net/lwm2m.h>
#include <zcbor_common.h>
#include <zcbor_encode.h>
#include <zcbor_decode.h>
#include <zcbor_bulk/zcbor_bulk_priv.h>
#include <lwm2m_transport.h>
#include <lwm2m_engine.h>
#include <lcz_bluetooth.h>
#include <lcz_lwm2m_client.h>
#include <lcz_lwm2m_gateway_obj.h>

#if defined(CONFIG_ATTR)
#include <attr.h>
#endif

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
#include <lcz_pki_auth_smp.h>
#endif

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

#define BT_CONN_CODED_CREATE_CONN                                                                  \
	BT_CONN_LE_CREATE_PARAM(BT_CONN_LE_OPT_CODED | BT_CONN_LE_OPT_NO_1M,                       \
				BT_GAP_SCAN_FAST_INTERVAL, BT_GAP_SCAN_FAST_INTERVAL)

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_lwm2m_transport_ble_central_init(const struct device *dev);

static int lwm2m_transport_ble_central_setup(struct lwm2m_ctx *client_ctx, char *url,
					     bool is_firmware_uri);
static int lwm2m_transport_ble_central_open(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_ble_central_start(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_ble_central_suspend(struct lwm2m_ctx *client_ctx, bool should_close);
static int lwm2m_transport_ble_central_resume(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_ble_central_send(struct lwm2m_ctx *client_ctx, const uint8_t *data,
					    uint32_t datalen);
static int lwm2m_transport_ble_central_recv(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_ble_central_close(struct lwm2m_ctx *client_ctx);
static int lwm2m_transport_ble_central_is_connected(struct lwm2m_ctx *client_ctx);
static void lwm2m_transport_ble_central_tx_pending(struct lwm2m_ctx *client_ctx, bool pending);
static char *lwm2m_transport_ble_central_print_addr(struct lwm2m_ctx *client_ctx,
						    const struct sockaddr *addr);

static void smp_client_send_work_function(struct k_work *w);
static void smp_client_send_open_tunnel(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx);
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

static void auth_complete_cb(const bt_addr_le_t *addr, bool status);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static const struct lwm2m_transport_procedure ble_central_transport = {
	.setup = lwm2m_transport_ble_central_setup,
	.open = lwm2m_transport_ble_central_open,
	.start = lwm2m_transport_ble_central_start,
	.suspend = lwm2m_transport_ble_central_suspend,
	.resume = lwm2m_transport_ble_central_resume,
	.close = lwm2m_transport_ble_central_close,
	.send = lwm2m_transport_ble_central_send,
	.recv = lwm2m_transport_ble_central_recv,
	.is_connected = lwm2m_transport_ble_central_is_connected,
	.tx_pending = lwm2m_transport_ble_central_tx_pending,
	.print_addr = lwm2m_transport_ble_central_print_addr,
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

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
static struct lcz_pki_auth_smp_central_auth_callback_agent auth_cb_agent = {
	.cb = auth_complete_cb
};
#endif

/* Function pointers for controlling scanning */
static void (*scan_start_fn)(void) = NULL;
static void (*scan_stop_fn)(void) = NULL;

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

/** @brief Report an error for a device
 *
 * @param[in] pctx Proxy context for the device
 * @param[in] immed_block True if the device should be block immediately
 */
static void dev_error(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, bool immed_block)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);
	if (pdev != NULL) {
		/* Increment the count of failures */
		if (pdev->failure_count < CONFIG_LCZ_LWM2M_GATEWAY_PROXY_MAX_FAILURE_COUNT) {
			pdev->failure_count++;
		}

		/* If the count exceeds the limit, block the device */
		if (pdev->failure_count >= CONFIG_LCZ_LWM2M_GATEWAY_PROXY_MAX_FAILURE_COUNT) {
			immed_block = true;
		}

		/* If we're going to block the device, clear the failure count now */
		if (immed_block) {
			pdev->failure_count = 0;
		}
	}

	/* Block the device if needed */
	if (immed_block) {
		LOG_WRN("Adding device to temporary block list");
		lcz_lwm2m_gw_obj_add_blocklist(
			pctx->dev_idx, CONFIG_LCZ_LWM2M_GATEWAY_PROXY_BLOCKLIST_TIME_SECONDS);
	}
}

/** @brief Report a successful exchange for a device
 *
 * @param[in] pctx Proxy context for the device
 */
static void dev_success(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);

	/* Clear the failure count */
	if (pdev != NULL) {
		pdev->failure_count = 0;
	}
}

/** @brief Set up the BLE central transport
 *
 * @param[in] client_ctx LwM2M context being set up
 * @param[in] url Server URL
 * @param[in] is_firmware_url True if this transport is for a firmware download
 *
 * @returns 0 on success, <0 on error
 */
static int lwm2m_transport_ble_central_setup(struct lwm2m_ctx *client_ctx, char *url,
					     bool is_firmware_uri)
{
	/* Nothing to do here. Everything is managed in start() */
	return 0;
}

/** @brief Open the BLE central transport
 *
 * @param[in] client_ctx LwM2M context being opened
 *
 * @returns 0 on success, <0 on error
 */
static int lwm2m_transport_ble_central_open(struct lwm2m_ctx *client_ctx)
{
	/* Nothing to do here. Everything is managed in start() */
	return 0;
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
	if (scan_stop_fn != NULL) {
		scan_stop_fn();
	}

	/* Open the BLE connection */
	err = bt_conn_le_create(lcz_lwm2m_gw_obj_get_address(pctx->dev_idx),
				(pctx->coded_phy) ? BT_CONN_CODED_CREATE_CONN :
							  BT_CONN_LE_CREATE_CONN,
				BT_LE_CONN_PARAM_DEFAULT, &(pctx->active_conn));
	if (err) {
		LOG_ERR("Create connection failed: %d", err);
		pctx->active_conn = NULL;

		/* Report the error */
		dev_error(pctx, false);

		/* Resume scanning */
		if (scan_start_fn != NULL) {
			scan_start_fn();
		}
		return err;
	} else {
		/* Create the eventfd file descriptor */
		client_ctx->sock_fd = eventfd(0, EFD_NONBLOCK);
		if (client_ctx->sock_fd < 0) {
			LOG_ERR("Failed to create eventfd socket: %d", client_ctx->sock_fd);

			bt_conn_disconnect(pctx->active_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
			bt_conn_unref(pctx->active_conn);
			pctx->active_conn = NULL;

			/* Report the error */
			dev_error(pctx, false);

			return client_ctx->sock_fd;
		} else {
			/* Add the socket to the socket table */
			lwm2m_sock_table_add(client_ctx);

			return 0;
		}
	}
}

/** @brief Suspend the BLE central transport
 *
 * @param[in] client_ctx LwM2M context being suspended
 * @param[in] should_close True if the socket should be closed, false otherwise
 *
 * @returns 0 on success, <0 on error
 */
static int lwm2m_transport_ble_central_suspend(struct lwm2m_ctx *client_ctx, bool should_close)
{
	/* Nothing to do here. We don't support suspend/resume in this transport. */
	return 0;
}

/** @brief Resume the BLE central transport
 *
 * @param[in] client_ctx LwM2M context being resumed
 *
 * @returns 0 on success, <0 on error
 */
static int lwm2m_transport_ble_central_resume(struct lwm2m_ctx *client_ctx)
{
	/* Nothing to do here. We don't support suspend/resume in this transport. */
	return 0;
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

	/* Remove the socket from the socket table */
	lwm2m_sock_table_del(client_ctx);

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

static int build_tunnel_data(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx,
			     LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev, struct queue_entry_t *item)
{
	zcbor_state_t zs[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];
	struct zcbor_string zstr;
	bool ok;
	int err = 0;
	struct lwm2m_gw_smp_buffer *smp_buf = NULL;
	size_t out_buffer_size;
	uint16_t payload_len;

	/* Calculate the size of the output buffer needed */
	out_buffer_size =
		sizeof(struct bt_dfu_smp_header) + LCZ_COAP_TUNNEL_CBOR_OVERHEAD + item->length;
	if (out_buffer_size > CONFIG_LCZ_LWM2M_TRANSPORT_BLE_MAX_PACKET) {
		LOG_ERR("build_tunnel_data: packet too large: %d", item->length);
		err = -EMSGSIZE;
	}

	/* Allocate memory for the message */
	if (err == 0) {
		smp_buf = (struct lwm2m_gw_smp_buffer *)k_malloc(out_buffer_size);
		if (smp_buf == NULL) {
			LOG_ERR("build_tunnel_data: failed to allocate %d bytes", out_buffer_size);
			err = -ENOMEM;
		}
	}

	/* Build the CBOR message */
	if (err == 0) {
		zcbor_new_state(zs, sizeof(zs) / sizeof(zs[0]), smp_buf->payload,
				(out_buffer_size - sizeof(struct bt_dfu_smp_header)), 1);

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
		if (ok == false) {
			LOG_ERR("build_tunnel_data: failed to encode CBOR");
			err = -ENOMEM;
		}
	}

	if (err == 0) {
		payload_len = (size_t)(zs[0].payload - smp_buf->payload);

		/* Fill in SMP message header */
		smp_buf->header.op = MGMT_OP_WRITE;
		smp_buf->header.flags = 0;
		smp_buf->header.len_h8 = (uint8_t)((payload_len >> 8) & 0xFF);
		smp_buf->header.len_l8 = (uint8_t)((payload_len >> 0) & 0xFF);
		smp_buf->header.group_h8 =
			(uint8_t)((CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 8) & 0xFF);
		smp_buf->header.group_l8 =
			(uint8_t)((CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 0) & 0xFF);
		smp_buf->header.seq = 0;
		smp_buf->header.id = LCZ_COAP_MGMT_ID_TUNNEL_DATA;

		err = bt_dfu_smp_command(&(pctx->smp_client), smp_client_resp_handler,
					 sizeof(smp_buf->header) + payload_len, smp_buf);
		if (err == 0) {
			pctx->flags |= CTX_FLAG_CLIENT_TUNNEL_BUSY;
		} else {
			LOG_ERR("build_tunnel_data: Failed to send tunnel data message: %d", err);
		}
	}

	/* Free any memory that we allocated */
	if (smp_buf != NULL) {
		k_free(smp_buf);
	}

	return err;
}

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
static int build_tunnel_enc_data(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx,
				 LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev, struct queue_entry_t *item,
				 psa_key_id_t aead_key)
{
	zcbor_state_t zs[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];
	struct zcbor_string zstr;
	bool ok;
	int err = 0;
	struct lwm2m_gw_smp_buffer *smp_buf = NULL;
	uint16_t payload_len;
	size_t nonce_len;
	size_t ciphertext_size;
	size_t out_buffer_size;
	size_t ciphertext_out_size;
	uint8_t *ciphertext = NULL;

	/* Calculate the size of the encrypted output */
	nonce_len = PSA_AEAD_NONCE_LENGTH(LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE,
					  LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG);
	ciphertext_size =
		nonce_len + PSA_AEAD_ENCRYPT_OUTPUT_SIZE(LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE,
							 LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG,
							 item->length);

	/*
	 * Calculate the size of the output buffer needed
	 *
	 * The output buffer is the SMP header, some overhead for CBOR encoding, and the size
	 * of the ciphertext.
	 */
	out_buffer_size =
		sizeof(struct bt_dfu_smp_header) + LCZ_COAP_TUNNEL_CBOR_OVERHEAD + ciphertext_size;
	if (out_buffer_size > CONFIG_LCZ_LWM2M_TRANSPORT_BLE_MAX_PACKET) {
		LOG_ERR("build_tunnel_enc_data: packet too large: %d", item->length);
		err = -EMSGSIZE;
	}

	/* Allocate memory for the message */
	if (err == 0) {
		smp_buf = (struct lwm2m_gw_smp_buffer *)k_malloc(out_buffer_size);
		if (smp_buf == NULL) {
			LOG_ERR("build_tunnel_enc_data: failed to allocate %d bytes",
				out_buffer_size);
			err = -ENOMEM;
		}
	}

	/* Allocate memory for the ciphertext */
	if (err == 0) {
		ciphertext = (uint8_t *)k_malloc(ciphertext_size);
		if (ciphertext == NULL) {
			LOG_ERR("build_tunnel_enc_data: failed to allocate ciphertext buffer of %d bytes",
				ciphertext_size);
			err = -ENOMEM;
		}
	}

	/* Generate the nonce */
	if (err == 0) {
		err = psa_generate_random(ciphertext, nonce_len);
		if (err != PSA_SUCCESS) {
			LOG_ERR("build_tunnel_enc_data: generate random nonce failed: %d", err);
		}
	}

	/* Encrypt the data */
	if (err == 0) {
		err = psa_aead_encrypt(aead_key, LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG, ciphertext,
				       nonce_len, (uint8_t *)&(pdev->tunnel_id),
				       sizeof(pdev->tunnel_id), item->data, item->length,
				       ciphertext + nonce_len, ciphertext_size - nonce_len,
				       &ciphertext_out_size);
		if (err != PSA_SUCCESS) {
			LOG_ERR("build_tunnel_enc_data: failed to encrypt: %d", err);
		}
	}

	/* Build the CBOR message */
	if (err == 0) {
		zcbor_new_state(zs, sizeof(zs) / sizeof(zs[0]), smp_buf->payload,
				(out_buffer_size - sizeof(struct bt_dfu_smp_header)), 1);
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
			zstr.len = ciphertext_size;
			zstr.value = ciphertext;
			ok = zcbor_bstr_encode(zs, &zstr);
		}
		if (ok) {
			ok = zcbor_map_end_encode(zs, 1);
		}
		if (ok == false) {
			LOG_ERR("build_tunnel_enc_data: failed to encode CBOR");
			err = -ENOMEM;
		}
	}

	if (err == 0) {
		payload_len = (size_t)(zs[0].payload - smp_buf->payload);

		/* Fill in SMP message header */
		smp_buf->header.op = MGMT_OP_WRITE;
		smp_buf->header.flags = 0;
		smp_buf->header.len_h8 = (uint8_t)((payload_len >> 8) & 0xFF);
		smp_buf->header.len_l8 = (uint8_t)((payload_len >> 0) & 0xFF);
		smp_buf->header.group_h8 =
			(uint8_t)((CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 8) & 0xFF);
		smp_buf->header.group_l8 =
			(uint8_t)((CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 0) & 0xFF);
		smp_buf->header.seq = 0;
		smp_buf->header.id = LCZ_COAP_MGMT_ID_TUNNEL_ENC_DATA;

		err = bt_dfu_smp_command(&(pctx->smp_client), smp_client_resp_handler,
					 sizeof(smp_buf->header) + payload_len, smp_buf);
		if (err == 0) {
			pctx->flags |= CTX_FLAG_CLIENT_TUNNEL_BUSY;
		} else {
			LOG_ERR("Failed to send tunnel encrypted data message: %d", err);
		}
	}

	/* Free the memory that we allocated */
	if (ciphertext != NULL) {
		k_free(ciphertext);
	}
	if (smp_buf != NULL) {
		k_free(smp_buf);
	}

	return err;
}
#endif

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
	int err = 0;
	struct queue_entry_t *item;
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
	psa_key_id_t aead_key = PSA_KEY_HANDLE_INIT;
#endif

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&(pctx->lock), K_FOREVER);

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);

	if ((pctx->flags & CTX_FLAG_CLIENT_TUNNEL_OPEN) == 0) {
		smp_client_send_open_tunnel(pctx);
	} else {
		/* Remove the first item from the transmit queue */
		item = k_fifo_get(&(pctx->tx_queue), K_NO_WAIT);
		if (item != NULL) {
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
			if ((pctx->flags & CTX_FLAG_CLIENT_AUTHORIZED) != 0) {
				err = lcz_pki_auth_smp_central_get_keys(
					bt_conn_get_dst(pctx->active_conn), &aead_key, NULL, NULL);
				if (err == 0) {
					err = build_tunnel_enc_data(pctx, pdev, item, aead_key);
				} else {
					LOG_ERR("Could not retrieve session keys: %d", err);
				}
			} else
#endif
			{
				err = build_tunnel_data(pctx, pdev, item);
			}

			/* Free the queue item memory */
			k_free(item);
		}
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&(pctx->lock));

	if (err) {
		/* Report the error */
		dev_error(pctx, false);

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
	struct lwm2m_gw_smp_buffer *smp_buf = NULL;
	uint16_t payload_len;
	size_t buffer_size;

	/* Allocate memory for the message */
	buffer_size = sizeof(struct bt_dfu_smp_header) + LCZ_COAP_TUNNEL_CBOR_OVERHEAD;
	smp_buf = (struct lwm2m_gw_smp_buffer *)k_malloc(buffer_size);
	if (smp_buf == NULL) {
		LOG_ERR("smp_client_send_open_tunnel: alloc failed");
		return;
	}

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&(pctx->lock), K_FOREVER);

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);

	/* Build the CBOR message */
	zcbor_new_state(zs, sizeof(zs) / sizeof(zs[0]), smp_buf->payload,
			LCZ_COAP_TUNNEL_CBOR_OVERHEAD, 1);
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

	payload_len = (size_t)(zs[0].payload - smp_buf->payload);

	/* Fill in SMP message header */
	smp_buf->header.op = MGMT_OP_WRITE;
	smp_buf->header.flags = 0;
	smp_buf->header.len_h8 = (uint8_t)((payload_len >> 8) & 0xFF);
	smp_buf->header.len_l8 = (uint8_t)((payload_len >> 0) & 0xFF);
	smp_buf->header.group_h8 =
		(uint8_t)((CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 8) & 0xFF);
	smp_buf->header.group_l8 =
		(uint8_t)((CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP >> 0) & 0xFF);
	smp_buf->header.seq = 0;
	smp_buf->header.id = LCZ_COAP_MGMT_ID_OPEN_TUNNEL;

	if (ok) {
		err = bt_dfu_smp_command(&(pctx->smp_client), smp_client_resp_handler,
					 sizeof(smp_buf->header) + payload_len, smp_buf);
		if (err == 0) {
			pctx->flags |= CTX_FLAG_CLIENT_TUNNEL_BUSY;
		} else {
			LOG_ERR("Failed to send open tunnel message: %d", err);
		}
	} else {
		LOG_ERR("Failed to encode open tunnel message");
		err = -ENOMEM;
	}

	if (smp_buf != NULL) {
		k_free(smp_buf);
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
	int rc = 0;
	bool ok;
	size_t decoded;

	struct zcbor_map_decode_key_val open_tunnel_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(i, zcbor_uint32_decode, &tunnel_id),
	};

	/* Parse the input */
	if (rc == 0) {
		ok = zcbor_map_decode_bulk(zsd, open_tunnel_decode, ARRAY_SIZE(open_tunnel_decode),
					   &decoded) == 0;
		if (ok == false) {
			LOG_ERR("handle_open_tunnel_resp: Invalid input");
			rc = -EINVAL;
		}
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
			LOG_WRN("handle_open_tunnel_resp: peripheral replied with tunnel id %d, expected %d",
				tunnel_id, pdev->tunnel_id);

			/* Record the error for this device */
			dev_error(pctx, true);

			rc = -EINVAL;
		}
	}

	if (rc == 0) {
		pctx->flags |= CTX_FLAG_CLIENT_TUNNEL_OPEN;
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
	struct zcbor_string data;
	eventfd_t event_val;
	bool ok;
	size_t decoded;
	int rc = 0;

	struct zcbor_map_decode_key_val tunnel_data_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(i, zcbor_uint32_decode, &tunnel_id),
		ZCBOR_MAP_DECODE_KEY_VAL(d, zcbor_bstr_decode, &data)
	};

	/* If we are authorized, we shouldn't be getting the unencrypted message */
	if ((pctx->flags & CTX_FLAG_CLIENT_AUTHORIZED) != 0) {
		LOG_ERR("handle_tunnel_data: Connection is authorized, expected encrypted tunnel data");
		rc = -EPERM;
	}

	/* Parse the input */
	if (rc == 0) {
		ok = zcbor_map_decode_bulk(zsd, tunnel_data_decode, ARRAY_SIZE(tunnel_data_decode),
					   &decoded) == 0;
		if (!ok || data.len == 0) {
			LOG_ERR("handle_tunnel_data: Invalid input");
			rc = -EINVAL;
		}
	}

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);

	/* If message is valid, handle it */
	if (rc == 0 && pdev != NULL && tunnel_id == pdev->tunnel_id) {
		/* Add it to our RX queue */
		if (add_to_queue(&(pctx->rx_queue), (uint8_t *)data.value, data.len) == 0) {
			/* Signal the event FD that data is ready to be read */
			event_val = EVENTFD_DATA_READY;
			(void)eventfd_write(pctx->ctx.sock_fd, event_val);
		}
	} else if (rc == 0) {
		LOG_ERR("handle_tunnel_data: peripheral used incorrect tunnel id %d", tunnel_id);
		rc = -EINVAL;
	}

	return rc;
}

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
/** @brief Handler for the Tunnel Encrypted Data message from the peripheral
 *
 * @param[in] pctx Proxy context pointer for the transport connection
 * @param[in] zsd ZCBOR state for decoding the Tunnel Data message
 *
 * @returns 0 on success, <0 on error.
 */
static int handle_tunnel_enc_data(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, zcbor_state_t *zsd)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;
	uint32_t tunnel_id;
	struct zcbor_string data;
	eventfd_t event_val;
	bool ok;
	size_t decoded;
	int rc = 0;
	psa_key_id_t aead_key = PSA_KEY_HANDLE_INIT;
	size_t nonce_len;
	size_t plaintext_size;
	size_t plaintext_out;
	uint8_t *plaintext = NULL;

	struct zcbor_map_decode_key_val tunnel_data_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(i, zcbor_uint32_decode, &tunnel_id),
		ZCBOR_MAP_DECODE_KEY_VAL(d, zcbor_bstr_decode, &data)
	};

	/* If we are not authorized, we shouldn't be getting the encrypted message */
	if ((pctx->flags & CTX_FLAG_CLIENT_AUTHORIZED) == 0) {
		LOG_ERR("handle_tunnel_enc_data: Connection is not authorized, expected unencrypted tunnel data");
		rc = -EPERM;
	}

	/* Parse the input */
	if (rc == 0) {
		ok = zcbor_map_decode_bulk(zsd, tunnel_data_decode, ARRAY_SIZE(tunnel_data_decode),
					   &decoded) == 0;
		if (!ok || data.len == 0) {
			LOG_ERR("handle_tunnel_enc_data: Invalid input");
			rc = -EINVAL;
		}
	}

	/* Get the device-specific data */
	pdev = lcz_lwm2m_gw_obj_get_dm_data(pctx->dev_idx);

	/* If message is valid, handle it */
	if (rc == 0 && pdev != NULL && tunnel_id == pdev->tunnel_id) {
		/* Calculate sizes */
		nonce_len = PSA_AEAD_NONCE_LENGTH(LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE,
						  LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG);
		plaintext_size = PSA_AEAD_DECRYPT_OUTPUT_SIZE(LCZ_PKI_AUTH_SMP_SESSION_KEY_TYPE,
							      LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG,
							      data.len - nonce_len);

		/* Allocate memory to hold the plaintext */
		plaintext = (uint8_t *)k_malloc(plaintext_size);
		if (plaintext == NULL) {
			LOG_ERR("handle_tunnel_enc_data: Cannot allocate plaintext buffer");
			rc = -ENOMEM;
		}

		/* Retrieve the key for this connection */
		if (rc == 0) {
			rc = lcz_pki_auth_smp_central_get_keys(bt_conn_get_dst(pctx->active_conn),
							       &aead_key, NULL, NULL);
			if (rc != 0) {
				LOG_ERR("handle_tunnel_enc_data: Could not retrieve keys: %d", rc);
			}
		}

		/* Decrypt the data */
		if (rc == 0) {
			rc = psa_aead_decrypt(aead_key, LCZ_PKI_AUTH_SMP_SESSION_AEAD_KEY_ALG,
					      data.value, nonce_len, (uint8_t *)&(pdev->tunnel_id),
					      sizeof(pdev->tunnel_id), data.value + nonce_len,
					      data.len - nonce_len, plaintext, plaintext_size,
					      &plaintext_out);
			if (rc != PSA_SUCCESS) {
				LOG_ERR("handle_tunnel_enc_data: failed to decrypt: %d", rc);
			}
		}

		/* Add it to our RX queue */
		if (rc == 0) {
			if (add_to_queue(&(pctx->rx_queue), plaintext, plaintext_out) == 0) {
				/* Signal the event FD that data is ready to be read */
				event_val = EVENTFD_DATA_READY;
				(void)eventfd_write(pctx->ctx.sock_fd, event_val);
			}
		}

		/* Free the memory that we allocated */
		if (plaintext != NULL) {
			k_free(plaintext);
		}
	} else if (rc == 0) {
		LOG_ERR("handle_tunnel_enc_data: peripheral used incorrect tunnel id %d",
			tunnel_id);
		rc = -EINVAL;
	}

	return rc;
}
#endif

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
	int rc = 0;
	bool ok;
	size_t decoded;

	struct zcbor_map_decode_key_val tunnel_data_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(i, zcbor_uint32_decode, &tunnel_id),
	};

	/* Parse the input */
	if (rc == 0) {
		ok = zcbor_map_decode_bulk(zsd, tunnel_data_decode, ARRAY_SIZE(tunnel_data_decode),
					   &decoded) == 0;
		if (ok == false) {
			LOG_ERR("handle_tunnel_data_resp: decode failed");
			rc = -EINVAL;
		}
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

	/* If we were successful, clear any fault counts */
	if (rc == 0) {
		dev_success(pctx);
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
	int rc = 0;
	bool ok;
	size_t decoded;

	struct zcbor_map_decode_key_val close_tunnel_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(i, zcbor_uint32_decode, &tunnel_id),
	};

	/* Parse the input */
	if (rc == 0) {
		ok = zcbor_map_decode_bulk(zsd, close_tunnel_decode,
					   ARRAY_SIZE(close_tunnel_decode), &decoded) == 0;
		if (ok == false) {
			LOG_ERR("handle_close_tunnel_resp: decode failed");
			rc = -EINVAL;
		}
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

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
/** @brief Handler for the Tunnel Encrypted Data response message from the peripheral
 *
 * @param[in] pctx Proxy context pointer for the transport connection
 * @param[in] zsd ZCBOR state for decoding the Tunnel Data response message
 *
 * @returns 0 on success, <0 on error.
 */
static int handle_tunnel_enc_data_resp(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx, zcbor_state_t *zsd)
{
	LCZ_LWM2M_GATEWAY_PROXY_DEV_T *pdev;
	uint32_t tunnel_id = 0;
	int rc = 0;
	bool ok;
	size_t decoded;

	struct zcbor_map_decode_key_val tunnel_data_decode[] = {
		ZCBOR_MAP_DECODE_KEY_VAL(i, zcbor_uint32_decode, &tunnel_id),
	};

	/* Parse the input */
	if (rc == 0) {
		ok = zcbor_map_decode_bulk(zsd, tunnel_data_decode, ARRAY_SIZE(tunnel_data_decode),
					   &decoded) == 0;
		if (ok == false) {
			LOG_ERR("handle_tunnel_enc_data_resp: decode failed");
			rc = -EINVAL;
		}
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
			LOG_ERR("handle_tunnel_enc_data_resp: peripheral returned tunnel id %d",
				tunnel_id);
			rc = -EINVAL;
		}
	}

	/* If we were successful, clear any fault counts */
	if (rc == 0) {
		dev_success(pctx);
	}

	return rc;
}
#endif

/** @brief Handler for a received CoAP tunnel SMP message from the peripheral
 *
 * @param[in] pctx Proxy context pointer for the transport connection
 *
 * @returns 0 on success, <0 on error.
 */
static int handle_smp_message(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx)
{
	uint16_t payload_len = ((uint16_t)pctx->smp_rsp_buff->header.len_h8) << 8 |
			       pctx->smp_rsp_buff->header.len_l8;
	int err = -EINVAL;
	zcbor_state_t states[CONFIG_MGMT_MAX_DECODING_LEVELS + 2];

	/* Initialize the CBOR reader */
	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), pctx->smp_rsp_buff->payload,
			payload_len, 1);

	if (pctx->smp_rsp_buff->header.op == MGMT_OP_WRITE_RSP) {
		switch (pctx->smp_rsp_buff->header.id) {
		case LCZ_COAP_MGMT_ID_OPEN_TUNNEL:
			err = handle_open_tunnel_resp(pctx, states);
			break;
		case LCZ_COAP_MGMT_ID_TUNNEL_DATA:
			err = handle_tunnel_data_resp(pctx, states);
			break;
		case LCZ_COAP_MGMT_ID_CLOSE_TUNNEL:
			err = handle_close_tunnel_resp(pctx, states);
			break;
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
		case LCZ_COAP_MGMT_ID_TUNNEL_ENC_DATA:
			err = handle_tunnel_enc_data_resp(pctx, states);
			break;
#endif
		default:
			LOG_ERR("Unknown SMP write response ID %d", pctx->smp_rsp_buff->header.id);
			break;
		}
	} else if (pctx->smp_rsp_buff->header.op == LCZ_COAP_MGMT_OP_NOTIFY) {
		switch (pctx->smp_rsp_buff->header.id) {
		case LCZ_COAP_MGMT_ID_TUNNEL_DATA:
			err = handle_tunnel_data(pctx, states);
			break;
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
		case LCZ_COAP_MGMT_ID_TUNNEL_ENC_DATA:
			err = handle_tunnel_enc_data(pctx, states);
			break;
#endif
		default:
			LOG_ERR("Unknown SMP notify ID %d", pctx->smp_rsp_buff->header.id);
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
	uint8_t *p_outdata;
	const struct bt_dfu_smp_rsp_state *rsp_state;
	int err = 0;

	/* Acquire a mutex lock for our data */
	k_mutex_lock(&(pctx->lock), K_FOREVER);

	/* Get the current response state */
	rsp_state = bt_dfu_smp_rsp_state(dfu_smp);

	/* Make sure a reassembly buffer is available */
	if (pctx->smp_rsp_buff != NULL) {
		if (rsp_state->offset == 0) {
			LOG_ERR("smp_client_resp_handler: New SMP request, but unfinished reassembly exists.");
		}
	} else {
		if (rsp_state->offset != 0) {
			LOG_ERR("smp_client_resp_handler: Continued SMP request, but no reassembly buffer exists.");
			err = -EINVAL;
		}
		if (err == 0) {
			pctx->smp_rsp_buff = (struct lwm2m_gw_smp_buffer *)k_malloc(
				CONFIG_LCZ_LWM2M_TRANSPORT_BLE_MAX_PACKET);
			if (pctx->smp_rsp_buff == NULL) {
				LOG_ERR("smp_client_resp_handler: Could not allocate reassembly buffer");
				err = -ENOMEM;
			}
		}
	}

	/* Copy the new data in our response buffer */
	if (err == 0) {
		p_outdata = (uint8_t *)pctx->smp_rsp_buff;
		if (rsp_state->offset + rsp_state->chunk_size >
		    CONFIG_LCZ_LWM2M_TRANSPORT_BLE_MAX_PACKET) {
			LOG_ERR("smp_client_resp_handler: Reassembly buffer overflow");
			err = -ENOMEM;
		} else {
			p_outdata += rsp_state->offset;
			memcpy(p_outdata, rsp_state->data, rsp_state->chunk_size);
		}
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
		uint16_t group = ((uint16_t)pctx->smp_rsp_buff->header.group_h8) << 8 |
				 pctx->smp_rsp_buff->header.group_l8;
		if (group != CONFIG_LCZ_LWM2M_TRANSPORT_BLE_SMP_GROUP) {
			LOG_ERR("SMP response has wrong group");
			err = -EINVAL;
		}
	}

	/* Handle the write response */
	if (err == 0 && pctx->smp_rsp_buff->header.op == MGMT_OP_WRITE_RSP) {
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
	else if (err == 0 && pctx->smp_rsp_buff->header.op == LCZ_COAP_MGMT_OP_NOTIFY) {
		/* Process the recevied message */
		err = handle_smp_message(pctx);
	}

	/* Any other operations are errors */
	else if (err == 0) {
		LOG_ERR("Invalid SMP operation %d", pctx->smp_rsp_buff->header.op);
		err = -EINVAL;
	}

	/* Free the reassembly buffer */
	if ((err != -EAGAIN) && (pctx->smp_rsp_buff != NULL)) {
		k_free(pctx->smp_rsp_buff);
		pctx->smp_rsp_buff = NULL;
	}

	/* Release the mutex lock for our data */
	k_mutex_unlock(&(pctx->lock));

	/* Handle any errors from above */
	if (err != 0 && err != -EAGAIN) {
		/* Report the error */
		dev_error(pctx, false);

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

	/* Report the error */
	dev_error(pctx, false);

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

		/* Report the error */
		dev_error(pctx, false);

		if (pctx->ctx.fault_cb != NULL) {
			pctx->ctx.fault_cb(&(pctx->ctx), conn_err);
		}

		/* Restart scanning */
		if (scan_start_fn != NULL) {
			scan_start_fn();
		}
	} else if (pctx != NULL) {
		/* Restart scanning */
		if (scan_start_fn != NULL) {
			scan_start_fn();
		}

		/* Enable security on the connection */
		err = bt_conn_set_security(conn, BT_SECURITY_L2);
		if (err != 0) {
			LOG_ERR("Failed to set security: %d", err);
		}

		/* Request the data length update */
		if (err == 0) {
			err = bt_conn_le_data_len_update(conn, BT_LE_DATA_LEN_PARAM_MAX);
			if (err != 0) {
				LOG_ERR("Data length update failed: %d", err);
			}
		}

		/* Exchange MTU sizes */
		if (err == 0) {
			err = bt_gatt_exchange_mtu(
				conn, (struct bt_gatt_exchange_params *)&exchange_params);
			if (err != 0) {
				LOG_ERR("MTU exchange failed: %d", err);
			}
		}

		/* Start discovery of the SMP service */
		if (err == 0) {
			err = bt_gatt_dm_start(conn, BT_UUID_DFU_SMP_SERVICE, &discovery_cb, pctx);
			if (err != 0) {
				LOG_ERR("Could not start discovery: %d", err);
			}
		}

		if (err != 0) {
			/* Report the error */
			dev_error(pctx, false);

			if (pctx->ctx.fault_cb != NULL) {
				pctx->ctx.fault_cb(&(pctx->ctx), err);
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
		if (scan_start_fn != NULL) {
			scan_start_fn();
		}

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
		/* If the security change was successful, start the authorization process */
		if (level == BT_SECURITY_L2 && err == BT_SECURITY_ERR_SUCCESS) {
			/* Client tunnel is now secure */
			pctx->flags |= CTX_FLAG_CLIENT_SECURE;
			pctx->flags &= ~CTX_FLAG_CLIENT_TUNNEL_BUSY;

			/* If connection is open, start the authorization process */
			if ((pctx->flags & (CTX_FLAG_CLIENT_SECURE | CTX_FLAG_CLIENT_DISCOVER)) ==
			    (CTX_FLAG_CLIENT_SECURE | CTX_FLAG_CLIENT_DISCOVER)) {
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
				err = lcz_pki_auth_smp_central_start_auth(&(pctx->smp_client));
				if (err != 0) {
					LOG_ERR("Could not start SMP authorization: %d", err);
					auth_complete_cb(bt_conn_get_dst(conn), false);
				}
#else
				/* Assume authentication failed */
				auth_complete_cb(bt_conn_get_dst(conn), false);
#endif
			}
		} else {
			LOG_ERR("bt_security_changed: fail with level %d err %d", level, err);

			/* Try unpairing this device if this happens */
			(void)bt_unpair(BT_ID_DEFAULT, bt_conn_get_dst(conn));

			/* Report the error */
			dev_error(pctx, false);

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

		/* Report the error */
		dev_error(pctx, false);

		if (pctx->ctx.fault_cb != NULL) {
			pctx->ctx.fault_cb(&(pctx->ctx), err);
		}
	} else {
		err = bt_gatt_dm_data_release(dm);
		if (err) {
			LOG_ERR("Could not release the discovery data, error: %d", err);

			/* Report the error */
			dev_error(pctx, false);

			if (pctx->ctx.fault_cb != NULL) {
				pctx->ctx.fault_cb(&(pctx->ctx), err);
			}
		}

		/* Client tunnel discovery is complete */
		pctx->flags |= CTX_FLAG_CLIENT_DISCOVER;
		pctx->flags &= ~CTX_FLAG_CLIENT_TUNNEL_BUSY;

		/* If connection is open, start the authorization process */
		if ((pctx->flags & (CTX_FLAG_CLIENT_SECURE | CTX_FLAG_CLIENT_DISCOVER)) ==
		    (CTX_FLAG_CLIENT_SECURE | CTX_FLAG_CLIENT_DISCOVER)) {
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
			err = lcz_pki_auth_smp_central_start_auth(&(pctx->smp_client));
			if (err != 0) {
				LOG_ERR("Could not start SMP authorization: %d", err);
				auth_complete_cb(bt_conn_get_dst(pctx->active_conn), false);
			}
#else
			/* Assume authentication failed */
			auth_complete_cb(bt_conn_get_dst(pctx->active_conn), false);
#endif
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

	/* Report the error */
	dev_error(pctx, false);

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

	/* Report the error */
	dev_error(pctx, false);

	if (pctx->ctx.fault_cb != NULL) {
		pctx->ctx.fault_cb(&(pctx->ctx), -ENOENT);
	}
}

static void auth_complete_cb(const bt_addr_le_t *addr, bool status)
{
	LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx;
	bool auth_required = false;

	/* Read the attribute if it exists */
#if defined(ATTR_ID_gw_smp_auth_req)
	auth_required = *(bool *)attr_get_quasi_static(ATTR_ID_gw_smp_auth_req);
#endif

	/* Look up our context based on the connection */
	pctx = lcz_lwm2m_gateway_proxy_addr_to_context(addr);
	if (pctx != NULL) {
		if (status) {
			pctx->flags |= CTX_FLAG_CLIENT_AUTHORIZED;
			k_work_submit(&(pctx->tunnel_tx_work));
		} else if (auth_required == true) {
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
			LOG_ERR("The SMP authentication procedure failed");
#else
			LOG_ERR("SMP authentication was required, but not compiled in");
#endif

			/* Report the error */
			dev_error(pctx, false);

			if (pctx->ctx.fault_cb != NULL) {
				pctx->ctx.fault_cb(&(pctx->ctx), -ENOENT);
			}
		} else {
#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
			LOG_WRN("SMP authentication failed, but was not required");
#endif
			k_work_submit(&(pctx->tunnel_tx_work));
		}
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

#if defined(CONFIG_LCZ_PKI_AUTH_SMP_CENTRAL)
	/* Register for authorization callbacks */
	lcz_pki_auth_smp_central_register_handler(&auth_cb_agent);
#endif

	/* Register our transport with the LwM2M engine */
	err = lwm2m_transport_register("ble_central",
				       (struct lwm2m_transport_procedure *)&ble_central_transport);
	if (err) {
		LOG_ERR("Failed to register BLE central transport: %d", err);
	}

	return err;
}

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
void lcz_lwm2m_gateway_proxy_reg_scan_fns(void (*start_fn)(void), void (*stop_fn)(void))
{
	scan_start_fn = start_fn;
	scan_stop_fn = stop_fn;
}
