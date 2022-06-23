/**
 * @file lcz_lwm2m_gateway_proxy_scan.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_lwm2m_gateway_proxy_scan, CONFIG_LCZ_LWM2M_GATEWAY_PROXY_LOG_LEVEL);

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zephyr.h>
#include <init.h>
#include <bluetooth/addr.h>

#include "lcz_bt_scan.h"
#include "lcz_sensor_event.h"
#include "lcz_sensor_adv_format.h"
#include "lcz_sensor_adv_match.h"
#include "lcz_lwm2m_gateway_proxy.h"
#include "lcz_lwm2m_gateway_proxy_scan.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define SCAN_RESTART_DELAY_SECONDS 2

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static int lcz_lwm2m_gateway_proxy_scan_init(const struct device *device);
static void ad_filter(const bt_addr_le_t *addr, LczSensorAdEvent_t *p, int8_t rssi);
static void ad_handler(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
		       struct net_buf_simple *ad);
static void scan_restart_work_handler(struct k_work *work);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static int scan_user_id = -1;
static K_WORK_DELAYABLE_DEFINE(scan_restart_work, scan_restart_work_handler);

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
void lcz_lwm2m_gateway_proxy_scan_resume(void)
{
	int r;
	if (scan_user_id >= 0 && lcz_bt_scan_active() == false) {
		r = lcz_bt_scan_restart(scan_user_id);
		if (r != 0) {
			LOG_WRN("Scan restart failed: %d. Retrying", r);
			k_work_reschedule(&scan_restart_work,
					  K_SECONDS(SCAN_RESTART_DELAY_SECONDS));
		}
	}
}

void lcz_lwm2m_gateway_proxy_scan_pause(void)
{
	if (scan_user_id >= 0 && lcz_bt_scan_active() == true) {
		k_work_cancel_delayable(&scan_restart_work);
		lcz_bt_scan_stop(scan_user_id);
	}
}

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
/** @brief Determine if incoming advertisement is relevent
 *
 * This function checks a flag in the advertisement to determine if the advertising device has
 * pending LwM2M traffic to send. The function passes the devices that do onto the gateway proxy
 * so that the traffic can be handled.
 *
 * @param[in] addr Bluetooth address of advertising device
 * @param[in] p Advertisement contents
 * @param[in] rssi RSSI of advertisement
 */
static void ad_filter(const bt_addr_le_t *addr, LczSensorAdEvent_t *p, int8_t rssi)
{
	/* If Alarm 4 flag is set, treat that as pending LwM2M traffic */
	/* Bug #22088: Update this to use the correct advertising flag */
	if (p != NULL && (p->flags & (1 << 11)) != 0) {
		lcz_lwm2m_gateway_proxy_device_ready(addr);
	}
}

/** @brief Process a received advertisement
 *
 * @param[in] addr Bluetooth address of advertising device
 * @param[in] rssi RSSI of advertisement
 * @param[in] type
 * @param[in] ad Advertisement contents
 */
static void ad_handler(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
		       struct net_buf_simple *ad)
{
	AdHandle_t handle =
		AdFind_Type(ad->data, ad->len, BT_DATA_MANUFACTURER_DATA, BT_DATA_INVALID);

	if (lcz_sensor_adv_match_1m(&handle)) {
		ad_filter(addr, (LczSensorAdEvent_t *)handle.pPayload, rssi);
	}

	if (lcz_sensor_adv_match_coded(&handle)) {
		/* The coded phy contains the TLVs of the 1M ad and scan response */
		LczSensorAdCoded_t *coded = (LczSensorAdCoded_t *)handle.pPayload;
		ad_filter(addr, &coded->ad, rssi);
	}
}

/** @brief Delayed work function for restarting the scan
 *
 * Sometimes the scan does not restart (stack busy, etc.), so whenever the scan restart
 * fails this work is scheduled to try again later.
 *
 * @param[in] work Work item
 */
static void scan_restart_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	lcz_lwm2m_gateway_proxy_scan_resume();
}

SYS_INIT(lcz_lwm2m_gateway_proxy_scan_init, APPLICATION,
	 CONFIG_LCZ_LWM2M_GATEWAY_PROXY_INIT_PRIORITY);
/**************************************************************************************************/
/* SYS INIT                                                                                       */
/**************************************************************************************************/
static int lcz_lwm2m_gateway_proxy_scan_init(const struct device *device)
{
	if (lcz_bt_scan_register(&scan_user_id, ad_handler) == false) {
		LOG_ERR("lcz_lwm2m_gateway_proxy_scan_init: failed to register with scanner");
	}

	return 0;
}
