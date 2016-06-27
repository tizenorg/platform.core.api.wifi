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

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <vconf/vconf.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>

#include "net_wifi_private.h"

#define WIFI_MAC_ADD_LENGTH	17
#define WIFI_MAC_ADD_PATH		"/sys/class/net/wlan0/address"

static __thread wifi_rssi_level_changed_cb rssi_level_changed_cb = NULL;
static __thread void *rssi_level_changed_user_data = NULL;

//LCOV_EXCL_START
static gboolean __rssi_level_changed_cb_idle(gpointer data)
{
	int rssi_level = 0;

	if (vconf_get_int(VCONFKEY_WIFI_STRENGTH, &rssi_level) != 0)
		return FALSE;

	if (rssi_level_changed_cb != NULL)
		rssi_level_changed_cb(rssi_level, rssi_level_changed_user_data);

	return FALSE;
}

static void __rssi_level_changed_cb(keynode_t *node, void *user_data)
{
	if (_wifi_is_init() != true) {
		WIFI_LOG(WIFI_ERROR, "Application is not registered" //LCOV_EXCL_LINE
				"If multi-threaded, thread integrity be broken.");
		return;
	}

	if (rssi_level_changed_cb != NULL)
		_wifi_callback_add(__rssi_level_changed_cb_idle, NULL);
}
//LCOV_EXCL_STOP

EXPORT_API int wifi_initialize(void)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_is_init() == true) {
		WIFI_LOG(WIFI_ERROR, "Already initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	rv = _wifi_libnet_init();
	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied"); //LCOV_EXCL_LINE
		return WIFI_ERROR_PERMISSION_DENIED; //LCOV_EXCL_LINE
	} else if (rv != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Init failed[%d]", rv); //LCOV_EXCL_LINE
		return WIFI_ERROR_OPERATION_FAILED; //LCOV_EXCL_LINE
	}

	_wifi_dbus_init();

	WIFI_LOG(WIFI_INFO, "Wi-Fi successfully initialized");

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_deinitialize(void)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (_wifi_libnet_deinit() == false) {
		WIFI_LOG(WIFI_ERROR, "Deinit failed"); //LCOV_EXCL_LINE
		return WIFI_ERROR_OPERATION_FAILED; //LCOV_EXCL_LINE
	}

	wifi_unset_rssi_level_changed_cb();
	_wifi_callback_cleanup();

	_wifi_dbus_deinit();

	WIFI_LOG(WIFI_INFO, "Wi-Fi successfully de-initialized");

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_activate(wifi_activated_cb callback, void* user_data)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	rv = _wifi_activate(callback, FALSE, user_data);
	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR, "Failed to activate Wi-Fi[%d]", rv); //LCOV_EXCL_LINE

	return rv;
}

EXPORT_API int wifi_activate_with_wifi_picker_tested(
		wifi_activated_cb callback, void* user_data)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized"); //LCOV_EXCL_LINE
		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE
	}

	rv = _wifi_activate(callback, TRUE, user_data);
	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR, "Failed to activate Wi-Fi[%d]", rv); //LCOV_EXCL_LINE

	return rv;
}

EXPORT_API int wifi_deactivate(wifi_deactivated_cb callback, void* user_data)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized"); //LCOV_EXCL_LINE
		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE
	}

	rv = _wifi_deactivate(callback, user_data);
	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR, "Wi-Fi deactivation failed"); //LCOV_EXCL_LINE

	return rv;
}

EXPORT_API int wifi_is_activated(bool* activated)
{
	int rv;
	wifi_device_state_e device_state;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (activated == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	rv = _wifi_libnet_get_wifi_device_state(&device_state);
	if (rv == WIFI_ERROR_NONE) {
		if (WIFI_DEVICE_STATE_DEACTIVATED == device_state)
			*activated = false;
		else
			*activated = true;
	}

	return rv;
}

EXPORT_API int wifi_get_mac_address(char** mac_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (mac_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

#if defined TIZEN_TV
	FILE *fp = NULL;
	char buf[WIFI_MAC_ADD_LENGTH + 1];
	if (0 == access(WIFI_MAC_ADD_PATH, F_OK))
		fp = fopen(WIFI_MAC_ADD_PATH, "r");

	if (fp == NULL) {
		WIFI_LOG(WIFI_ERROR, "Failed to open file" //LCOV_EXCL_LINE
				" %s\n", WIFI_MAC_ADD_PATH);
		return WIFI_ERROR_OPERATION_FAILED;
	}

	if (fgets(buf, sizeof(buf), fp) == NULL) {
		WIFI_LOG(WIFI_ERROR, "Failed to get MAC"
				" info from %s\n", WIFI_MAC_ADD_PATH); //LCOV_EXCL_LINE
		fclose(fp); //LCOV_EXCL_LINE
		return WIFI_ERROR_OPERATION_FAILED;
	}

	WIFI_LOG(WIFI_INFO, "%s : %s\n", WIFI_MAC_ADD_PATH, buf);

	*mac_address = (char *)g_try_malloc0(WIFI_MAC_ADD_LENGTH + 1);
	if (*mac_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "malloc() failed"); //LCOV_EXCL_LINE
		fclose(fp); //LCOV_EXCL_LINE
		return WIFI_ERROR_OUT_OF_MEMORY;
	}
	g_strlcpy(*mac_address, buf, WIFI_MAC_ADD_LENGTH + 1);
	fclose(fp);
#else
	*mac_address = vconf_get_str(VCONFKEY_WIFI_BSSID_ADDRESS);

	if (*mac_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "Failed to get vconf" //LCOV_EXCL_LINE
			" from %s", VCONFKEY_WIFI_BSSID_ADDRESS);
		return WIFI_ERROR_OPERATION_FAILED; //LCOV_EXCL_LINE
	}
#endif

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_get_network_interface_name(char** name)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (name == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_get_intf_name(name);
}

EXPORT_API int wifi_scan(wifi_scan_finished_cb callback, void* user_data)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized"); //LCOV_EXCL_LINE
		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE
	}

	rv = _wifi_libnet_scan_request(callback, user_data);
	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR, "Wi-Fi scan failed"); //LCOV_EXCL_LINE

	return rv;
}

EXPORT_API int wifi_scan_specific_ap(const char* essid, wifi_scan_finished_cb callback, void* user_data)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (essid == NULL || callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized"); //LCOV_EXCL_LINE

		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE
	}

	rv = _wifi_libnet_scan_specific_ap(essid, callback, user_data);
	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR, "Wi-Fi hidden scan failed.\n"); //LCOV_EXCL_LINE

	return rv;
}



EXPORT_API int wifi_get_connected_ap(wifi_ap_h *ap)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (ap == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	rv = _wifi_libnet_get_connected_profile(ap);
	WIFI_LOG(WIFI_INFO, "Connected AP %p, rv %d", *ap, rv);

	return rv;
}

EXPORT_API int wifi_foreach_found_aps(wifi_found_ap_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_foreach_found_aps(callback, user_data);
}

EXPORT_API int wifi_foreach_found_specific_aps(wifi_found_ap_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_foreach_found_specific_aps(callback, user_data);
}

EXPORT_API int wifi_connect(wifi_ap_h ap, wifi_connected_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized"); //LCOV_EXCL_LINE
		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE
	}

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_open_profile(ap, callback, user_data);
}

EXPORT_API int wifi_disconnect(wifi_ap_h ap, wifi_disconnected_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized"); //LCOV_EXCL_LINE
		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE
	}

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_close_profile(ap, callback, user_data);
}

//LCOV_EXCL_START
EXPORT_API int wifi_connect_by_wps_pbc(wifi_ap_h ap, wifi_connected_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_connect_with_wps_pbc(ap, callback, user_data);
}

EXPORT_API int wifi_connect_by_wps_pin(wifi_ap_h ap, const char *pin, wifi_connected_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (NULL == pin || 0 == strlen(pin) || strlen(pin) > NET_WLAN_MAX_WPSPIN_LEN) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_connect_with_wps_pin(ap, pin, callback, user_data);
}
//LCOV_EXCL_STOP

EXPORT_API int wifi_forget_ap(wifi_ap_h ap)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized"); //LCOV_EXCL_LINE
		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE
	}

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_forget_ap(ap);
}

EXPORT_API int wifi_get_connection_state(wifi_connection_state_e *connection_state)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (connection_state == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_get_wifi_state(connection_state);
}

EXPORT_API int wifi_set_device_state_changed_cb(wifi_device_state_changed_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized"); //LCOV_EXCL_LINE
		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE
	}

	return _wifi_set_power_on_off_cb(callback, user_data);
}

EXPORT_API int wifi_unset_device_state_changed_cb(void)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	return _wifi_unset_power_on_off_cb();
}

EXPORT_API int wifi_set_background_scan_cb(wifi_scan_finished_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized"); //LCOV_EXCL_LINE
		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE
	}

	return _wifi_set_background_scan_cb(callback, user_data);
}

EXPORT_API int wifi_unset_background_scan_cb(void)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	return _wifi_unset_background_scan_cb();
}

EXPORT_API int wifi_set_connection_state_changed_cb(wifi_connection_state_changed_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized"); //LCOV_EXCL_LINE
		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE
	}

	return _wifi_set_connection_state_cb(callback, user_data);
}

EXPORT_API int wifi_unset_connection_state_changed_cb(void)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	return _wifi_unset_connection_state_cb();
}

EXPORT_API int wifi_set_rssi_level_changed_cb(wifi_rssi_level_changed_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (rssi_level_changed_cb == NULL)
		vconf_notify_key_changed(VCONFKEY_WIFI_STRENGTH, __rssi_level_changed_cb, NULL);
	else
		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE

	rssi_level_changed_cb = callback;
	rssi_level_changed_user_data = user_data;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_unset_rssi_level_changed_cb(void)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (rssi_level_changed_cb != NULL)
		vconf_ignore_key_changed(VCONFKEY_WIFI_STRENGTH, __rssi_level_changed_cb);
	else
		return WIFI_ERROR_INVALID_OPERATION; //LCOV_EXCL_LINE

	rssi_level_changed_cb = NULL;
	rssi_level_changed_user_data = NULL;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_connect_by_wps_pbc_without_ssid(wifi_connected_cb callback,
				void* user_data)
{
#if defined TIZEN_TV
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);
	WIFI_LOG(WIFI_INFO, "[App-->TizenMW] WiFi Connect by WPS_PBC without SSID\n");

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "[App<--TizenMW] Not initialized\n");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "[App<--TizenMW] Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_connect_with_wps_pbc_without_ssid(callback, user_data);
#else
	return WIFI_ERROR_NOT_SUPPORTED;
#endif
}

EXPORT_API int wifi_connect_by_wps_pin_without_ssid(const char *pin,
		wifi_connected_cb callback, void* user_data)
{

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);
	WIFI_LOG(WIFI_INFO, "[App-->TizenMW] WiFi Connect by WPS_PIN without SSID\n");

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "[App<--TizenMW] Not initialized\n");
		return WIFI_ERROR_INVALID_OPERATION;
	}


	if (callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "[App<--TizenMW] Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if ((NULL == pin) || ((strlen(pin) != 4) &&
				(strlen(pin) != NET_WLAN_MAX_WPSPIN_LEN))){
		WIFI_LOG(WIFI_ERROR, "[App<--TizenMW] Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_connect_with_wps_pin_without_ssid(pin,callback,user_data);
}

EXPORT_API int wifi_cancel_wps(void)
{

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);
	WIFI_LOG(WIFI_INFO, "[App-->TizenMW] cancel wps request\n");

	int rv;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "[App<--TizenMW] Not initialized\n");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	rv = _wifi_libnet_cancel_wps();

	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR,
			"[App<--TizenMW] Error!! WPS Cancel Request failed. rv[%d]\n",
			rv);

	return rv;
}

//LCOV_EXCL_START
EXPORT_API int wifi_tdls_disconnect(const char* peer_mac_addr)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);
	CHECK_FEATURE_SUPPORTED(WIFI_TDLS_FEATURE);

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (peer_mac_addr == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	int rv = 0;
	rv = net_wifi_tdls_disconnect(peer_mac_addr);

	if (rv != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Failed to disconnect tdls");
		return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_tdls_get_connected_peer(char** peer_mac_addr)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);
	CHECK_FEATURE_SUPPORTED(WIFI_TDLS_FEATURE);

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (peer_mac_addr == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	int rv = 0;
	rv = net_wifi_tdls_connected_peer(peer_mac_addr);

	if (rv != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Failed to get connected peer");
		return WIFI_ERROR_OPERATION_FAILED;
	}

	if (g_strcmp0(*peer_mac_addr, "00.00.00.00.00.00") == 0) {
		g_free(*peer_mac_addr);
		return WIFI_ERROR_NO_CONNECTION;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_tdls_set_state_changed_cb(wifi_tdls_state_changed_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);
	CHECK_FEATURE_SUPPORTED(WIFI_TDLS_FEATURE);
	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_tdls_unset_state_changed_cb(void)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);
	CHECK_FEATURE_SUPPORTED(WIFI_TDLS_FEATURE);
	return WIFI_ERROR_NONE;
}
//LCOV_EXCL_STOP
