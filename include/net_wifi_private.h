/*
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __NET_CONNECTION_PRIVATE_H__
#define __NET_CONNECTION_PRIVATE_H__

#include <dlog.h>

#include <connman-lib.h>
#include <connman-manager.h>
#include <connman-technology.h>
#include <connman-service.h>

#include "wifi.h"

#undef LOG_TAG
#define LOG_TAG "CAPI_NETWORK_WIFI"

#define WIFI_INFO	1
#define WIFI_ERROR	2
#define WIFI_WARN	3

#define WIFI_LOG(log_level, format, args...) \
	do { \
		switch (log_level) { \
		case WIFI_ERROR: \
			LOGE(format, ## args); \
			break; \
		case WIFI_WARN: \
			LOGW(format, ## args); \
			break; \
		default: \
			LOGI(format, ## args); \
		} \
	} while(0)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*****************************************************************************
 * 	Global Structures
 *****************************************************************************/
/**
 * This is the structure to connect with WPS network.
 */
typedef struct {
	/** PBC / PIN */
	net_wifi_wps_type_t type;

	/** Optional. This pin is needed when the user input PIN code */
	char pin[NET_WLAN_MAX_WPSPIN_LEN + 1];
} net_wifi_wps_info_t;

/**
 * This is the profile structure to connect hidden WiFi network.
 */
typedef struct {
	/** Basic feature */
	char essid[NET_WLAN_ESSID_LEN + 1];

	/** Infrastructure / ad-hoc / auto mode */
	wlan_connection_mode_type_t wlan_mode;

	/** Security mode and authentication info */
	wlan_security_info_t security_info;
} net_wifi_connection_info_t;

/**
 * This is the profile structure exposed to applications.
 */
typedef struct
{
	/** Profile name */
	char *essid;
} net_profile_info_t;


bool _wifi_libnet_init(void);
bool _wifi_libnet_deinit(void);
int _wifi_activate(wifi_activated_cb callback, void *user_data);
int _wifi_deactivate(wifi_deactivated_cb callback, void *user_data);

bool _wifi_libnet_check_ap_validity(wifi_ap_h ap_h);
void _wifi_libnet_add_to_ap_list(wifi_ap_h ap_h);
void _wifi_libnet_remove_from_ap_list(wifi_ap_h ap_h);
bool _wifi_libnet_check_profile_name_validity(const char *profile_name);

bool _wifi_libnet_get_wifi_device_state(wifi_device_state_e *device_state);
bool _wifi_libnet_get_wifi_state(wifi_connection_state_e* connection_state);
int _wifi_libnet_get_intf_name(char** name);
int _wifi_libnet_scan_request(wifi_scan_finished_cb callback, void *user_data);
int _wifi_libnet_scan_hidden_ap(const char *essid,
					wifi_scan_finished_cb callback, void *user_data);
int _wifi_libnet_get_connected_profile(wifi_ap_h *ap);
bool _wifi_libnet_foreach_found_aps(wifi_found_ap_cb callback, void *user_data);
bool _wifi_libnet_foreach_found_hidden_aps(wifi_found_ap_cb callback, void *user_data);

int _wifi_libnet_open_profile(wifi_ap_h ap_h, wifi_connected_cb callback, void *user_data);
int _wifi_libnet_close_profile(wifi_ap_h ap_h, wifi_disconnected_cb callback, void *user_data);
int _wifi_libnet_connect_with_wps(wifi_ap_h ap, wifi_connected_cb callback, void *user_data);
int _wifi_libnet_forget_ap(wifi_ap_h ap);

int _wifi_set_power_on_off_cb(wifi_device_state_changed_cb callback, void *user_data);
int _wifi_unset_power_on_off_cb(void);
int _wifi_set_background_scan_cb(wifi_scan_finished_cb callback, void *user_data);
int _wifi_unset_background_scan_cb(void);
int _wifi_set_connection_state_cb(wifi_connection_state_changed_cb callback, void *user_data);
int _wifi_unset_connection_state_cb();

/*int _wifi_update_ap_info(net_profile_info_t *ap_info);*/
wifi_connection_state_e _wifi_convert_to_ap_state(
					net_state_type_t state);

net_state_type_t _get_service_state_type(const char *state);

/*For connection which CAPI send some message to WiNet daemon*/
void _set_wifi_conn_info(net_wifi_connection_info_t *wifi_conn_info);
net_wifi_connection_info_t *_get_wifi_conn_info(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
