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
#include <network-cm-intf.h>
#include <network-wifi-intf.h>
#include <system_info.h>

#include "wifi.h"
#include "wifi_dbus_private.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#undef LOG_TAG
#define LOG_TAG "CAPI_NETWORK_WIFI"

#define WIFI_INFO	1
#define WIFI_ERROR	2
#define WIFI_WARN	3

#define WIFI_FEATURE	"http://tizen.org/feature/network.wifi"

#define CHECK_FEATURE_SUPPORTED(feature_name) \
	do { \
		int rv = _wifi_check_feature_supported(feature_name); \
		if( rv != WIFI_ERROR_NONE ) \
			return rv; \
	} while(0)

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

#define SECURE_WIFI_LOG(log_level, format, args...) \
	do { \
		switch (log_level) { \
		case WIFI_ERROR: \
			SECURE_LOGE(format, ## args); \
			break; \
		case WIFI_WARN: \
			SECURE_LOGW(format, ## args); \
			break; \
		default: \
			SECURE_LOGI(format, ## args); \
		} \
	} while(0)

bool _wifi_is_init(void);

int _wifi_libnet_init(void);
bool _wifi_libnet_deinit(void);
int _wifi_activate(wifi_activated_cb callback, gboolean wifi_picker_test, void *user_data);
int _wifi_deactivate(wifi_deactivated_cb callback, void *user_data);

bool _wifi_libnet_check_ap_validity(wifi_ap_h ap_h);
void _wifi_libnet_add_to_ap_list(wifi_ap_h ap_h);
void _wifi_libnet_remove_from_ap_list(wifi_ap_h ap_h);
bool _wifi_libnet_check_profile_name_validity(const char *profile_name);

int _wifi_libnet_get_wifi_device_state(wifi_device_state_e *device_state);
int _wifi_libnet_get_wifi_state(wifi_connection_state_e* connection_state);
int _wifi_libnet_get_intf_name(char** name);
int _wifi_libnet_scan_request(wifi_scan_finished_cb callback, void *user_data);
int _wifi_libnet_scan_specific_ap(const char *essid, wifi_scan_finished_cb callback, void *user_data);
int _wifi_libnet_get_connected_profile(wifi_ap_h *ap);
int _wifi_libnet_foreach_found_aps(wifi_found_ap_cb callback, void *user_data);
int _wifi_libnet_foreach_found_specific_aps(wifi_found_ap_cb callback, void *user_data);

int _wifi_libnet_open_profile(wifi_ap_h ap_h, wifi_connected_cb callback, void *user_data);
int _wifi_libnet_close_profile(wifi_ap_h ap_h, wifi_disconnected_cb callback, void *user_data);
int _wifi_libnet_connect_with_wps_pbc(wifi_ap_h ap,
		wifi_connected_cb callback, void *user_data);
int _wifi_libnet_connect_with_wps_pin(wifi_ap_h ap, const char *pin,
		wifi_connected_cb callback, void *user_data);
int _wifi_libnet_forget_ap(wifi_ap_h ap);

int _wifi_set_power_on_off_cb(wifi_device_state_changed_cb callback, void *user_data);
int _wifi_unset_power_on_off_cb(void);
int _wifi_set_background_scan_cb(wifi_scan_finished_cb callback, void *user_data);
int _wifi_unset_background_scan_cb(void);
int _wifi_set_connection_state_cb(wifi_connection_state_changed_cb callback, void *user_data);
int _wifi_unset_connection_state_cb();

int _wifi_update_ap_info(net_profile_info_t *ap_info);
wifi_connection_state_e _wifi_convert_to_ap_state(net_state_type_t state);

guint _wifi_callback_add(GSourceFunc func, gpointer user_data);
void _wifi_callback_cleanup(void);

int _wifi_check_feature_supported(const char *feature_name);

int        _wifi_dbus_init(void);
int        _wifi_dbus_deinit(void);
wifi_dbus *_wifi_get_dbus_handle(void);

int _wifi_set_tdls_connected_cb(wifi_tdls_connected_cb callback, void *user_data);
int _wifi_set_tdls_disconnected_cb(wifi_tdls_disconnected_cb callback, void *user_data);
int _wifi_unset_tdls_connected_cb(void);
int _wifi_unset_tdls_disconnected_cb(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
