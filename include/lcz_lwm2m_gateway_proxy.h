/**
 * @file lcz_lwm2m_gateway_proxy.h
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

#ifndef __LCZ_LWM2M_GATEWAY_PROXY_H__
#define __LCZ_LWM2M_GATEWAY_PROXY_H__

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <stddef.h>
#include <stdint.h>
#include <zephyr/zephyr.h>
#include <zephyr/types.h>
#include <zephyr/bluetooth/addr.h>
#include <bluetooth/services/dfu_smp.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/lwm2m.h>

#include <lcz_lwm2m_client.h>

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************************/
/* Global Constants, Macros and Type Definitions                                                  */
/**************************************************************************************************/
/* Device data flag definitions */
#define DEV_FLAG_DATA_READY 0x01

/* Proxy context flag definitions */
#define CTX_FLAG_ACTIVE 0x01
#define CTX_FLAG_INCOMING 0x02
#define CTX_FLAG_CLIENT_SECURE 0x04
#define CTX_FLAG_CLIENT_DISCOVER 0x08
#define CTX_FLAG_CLIENT_AUTHORIZED 0x10
#define CTX_FLAG_CLIENT_TUNNEL_OPEN 0x20
#define CTX_FLAG_CLIENT_TUNNEL_BUSY 0x40
#define CTX_FLAG_STOPPED 0x80

/* Buffer for SMP messages */
struct lwm2m_gw_smp_buffer {
	struct bt_dfu_smp_header header;
	uint8_t payload[1];
};

/* Queue entry for SMP receive queue */
struct lwm2m_gw_smp_buffer_queue {
	void *fifo_reserved;
	struct lwm2m_gw_smp_buffer buf;
};

/** @brief Data strorage for proxy device information */
typedef struct {
	/* SMP transport tunnel ID */
	uint32_t tunnel_id;

	/* Count of repeated connection failures */
	uint32_t failure_count;

	/* Device flags */
	uint8_t flags;

	/* Current PHY in use by the device */
	bool coded_phy;

	/* Queue of pending CoAP messages to device */
	struct k_fifo tx_queue;
} LCZ_LWM2M_GATEWAY_PROXY_DEV_T;

#define DEV_IDX_INVALID -1

/** @brief Data storage for proxy server instances */
typedef struct {
	uint8_t flags;

	int dev_idx;

	/* Type of advertisement used by the device */
	bool coded_phy;

	/* Used by the transport layer */
	struct lwm2m_ctx ctx;
	struct k_mutex lock;
	struct k_work tunnel_tx_work;
	struct k_fifo tx_queue;
	struct k_fifo rx_queue;
	struct bt_dfu_smp smp_client;
	struct bt_conn *active_conn;

	/* Buffer to hold SMP messages (replies and notifications) to be re-assembled */
	struct lwm2m_gw_smp_buffer_queue *smp_rsp_buff;
	struct k_fifo smp_rx_queue;
	struct k_work smp_rx_work;

	/* Pending messages from the device */
	struct coap_pending pendings[CONFIG_LWM2M_ENGINE_MAX_PENDING];
	struct coap_reply replies[CONFIG_LWM2M_ENGINE_MAX_REPLIES];

	/* Work for connection timeout */
	struct k_work_delayable conn_timeout_work;
} LCZ_LWM2M_GATEWAY_PROXY_CTX_T;

/* Byte in a CoAP reply where the response code goes */
#define COAP_REPLY_BYTE 1

/**************************************************************************************************/
/* Global Function Prototypes                                                                     */
/**************************************************************************************************/
/**
 * @brief Register scan start/stop control functions
 *
 * When the CoAP proxy needs to establish a BLE connection with a device, scanning must be stopped
 * and then restarted when the connection has been established. This function allows the
 * application to provide the start/stop functions that the CoAP proxy will call.
 *
 * @param[in] start_fn Function to call to resume scanning
 * @param[in] stop_fn Function to call to pause scanning
 */
void lcz_lwm2m_gateway_proxy_reg_scan_fns(void (*start_fn)(void), void (*stop_fn)(void));

/**
 * @brief Function to be called when a device has LwM2M traffic ready for the gateway
 *
 * @param[in] addr Bluetooth address of the device with traffic ready
 * @param[in] coded_phy true if the device is using the coded PHY, false if 1M PHY
 */
void lcz_lwm2m_gateway_proxy_device_ready(const bt_addr_le_t *addr, bool coded_phy);

/**
 * @brief Look up a proxy context given a BLE connection handle
 *
 * @param[in] conn BLE connection handle
 *
 * @returns a pointer to the context or NULL if the connection isn't
 * one that we know about.
 */
LCZ_LWM2M_GATEWAY_PROXY_CTX_T *lcz_lwm2m_gateway_proxy_conn_to_context(struct bt_conn *conn);

/**
 * @brief Look up a proxy context given a BLE address
 *
 * @param[in] addr BLE address
 *
 * @returns a pointer to the context or NULL if the connection isn't
 * one that we know about.
 */
LCZ_LWM2M_GATEWAY_PROXY_CTX_T *lcz_lwm2m_gateway_proxy_addr_to_context(const bt_addr_le_t *addr);

/**
 * @brief Close a proxy context
 *
 * @param[in] pctx Proxy context to close
 */
void lcz_lwm2m_gateway_proxy_close(LCZ_LWM2M_GATEWAY_PROXY_CTX_T *pctx);

/**
 * @brief Update LwM2M context to add proxy message handler
 *
 * Takes an existing LwM2M context (e.g., a proxy file transfer context) and
 * adds the gateway proxy message handler to it.
 *
 * @param[in] ctx LwM2M context to add the handler to
 */
void lcz_lwm2m_gateway_proxy_add_context(struct lwm2m_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* __LCZ_LWM2M_GATEWAY_PROXY_H__ */
