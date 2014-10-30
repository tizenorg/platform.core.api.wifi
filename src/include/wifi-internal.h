/*
* Network Wi-Fi library
*
* Copyright (c) 2014-2015 Intel Corporation. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*              http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

#ifndef __NET_CONNECTION_PRIVATE_H__
#define __NET_CONNECTION_PRIVATE_H__

#include <connman-lib-common.h>

#include "wifi.h"
#include "common.h"

#define LOGI(fmt, arg...) printf("%s:%d %s() " fmt "\n",  \
                               __FILE__, __LINE__, __func__, ## arg)
#define LOGW(fmt, arg...) printf("warning %s:%d %s() " fmt "\n", \
                               __FILE__, __LINE__, __func__, ## arg)
#define LOGE(fmt, arg...) printf("error %s:%d %s() " fmt "\n", \
                               __FILE__, __LINE__, __func__, ## arg)

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
int _wifi_libnet_scan_request(wifi_scan_finished_cb callback,
				  void *user_data);
int _wifi_libnet_scan_hidden_ap(const char *essid,
				    wifi_scan_finished_cb callback,
				    void *user_data);
int _wifi_libnet_get_connected_profile(wifi_ap_h *ap);
bool _wifi_libnet_foreach_found_aps(wifi_found_ap_cb callback,
					void *user_data);
bool _wifi_libnet_foreach_found_hidden_aps(wifi_found_ap_cb callback,
						void *user_data);

int _wifi_libnet_open_profile(wifi_ap_h ap_h,
				  wifi_connected_cb callback,
				  void *user_data);
int _wifi_libnet_close_profile(wifi_ap_h ap_h,
				   wifi_disconnected_cb callback,
				   void *user_data);
int _wifi_libnet_connect_with_wps(wifi_ap_h ap_h,
				      wifi_connected_cb callback,
				      void *user_data);
int _wifi_libnet_forget_ap(wifi_ap_h ap_h);

int _wifi_set_power_on_off_cb(wifi_device_state_changed_cb callback,
				  void *user_data);
int _wifi_unset_power_on_off_cb(void);
int _wifi_set_background_scan_cb(wifi_scan_finished_cb callback,
				     void *user_data);
int _wifi_unset_background_scan_cb(void);
int _wifi_set_connection_state_cb(
		wifi_connection_state_changed_cb callback, void *user_data);
int _wifi_unset_connection_state_cb();

wifi_connection_state_e _wifi_convert_to_ap_state(
					net_state_type_t state);
net_state_type_t _wifi_get_service_state_type(const char *state);

/*For connection which CAPI send some message to WiNet daemon*/
void _wifi_set_conn_info(net_wifi_connection_info_t *wifi_conn_info);
net_wifi_connection_info_t *_wifi_get_conn_info(void);

char *_wifi_get_ip_config_str(net_ip_config_type_t ip_config_type);
net_ip_config_type_t _wifi_get_ip_config_type(const char *config);
net_proxy_type_t _wifi_get_proxy_type(const char *proxy);
wlan_encryption_mode_type_t _wifi_get_encryption_type
					(const char *encryption_mode);
struct connman_service *_wifi_get_service_h(wifi_ap_h ap_h);
wifi_error_e _wifi_connman_lib_error2wifi_error(enum connman_lib_err err_type);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
