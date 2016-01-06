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

static __thread GSList *wifi_handle_list = NULL;

bool __wifi_check_handle_validity(wifi_h wifi)
{
	bool ret = false;

	if (wifi == NULL)
		return false;

	if (g_slist_find(wifi_handle_list, wifi) != NULL)
		ret = true;

	return ret;
}

static int __wifi_get_callback_count(wifi_handle_cb_e e)
{
	GSList *list;
	int count = 0;

	for (list = wifi_handle_list; list; list = list->next) {
		wifi_handle_s *local_handle = (wifi_handle_s *)list->data;
		switch (e) {
		case WIFI_DEVICE_STATE_CHANGED_CB:
			if (local_handle->device_state_cb) count++;
			break;
		case WIFI_SCAN_FINISHED_CB:
			if (local_handle->bg_scan_cb) count++;
			break;
		case WIFI_CONNECTION_STATE_CHANGED_CB:
			if (local_handle->connection_state_cb) count++;
			break;
		case WIFI_RSSI_LEVEL_CHANGED_CB:
			if (local_handle->rssi_level_changed_cb) count++;
			break;
		case WIFI_TDLS_STATE_CHANGED_CB:
			if (local_handle->tdls_state_changed_cb) count++;
			break;
		default:
			break;
		}
	}

	return count;
}

static void __wifi_device_state_changed_cb(wifi_device_state_e state, void *user_data)
{
	GSList *list;

	for (list = wifi_handle_list; list; list = list->next) {
		wifi_handle_s *local_handle = (wifi_handle_s *)list->data;
		if (local_handle->device_state_cb)
			local_handle->device_state_cb(state, local_handle->device_state_user_data);
	}
}

static int __wifi_set_device_state_changed_cb(wifi_h wifi,
			void *callback, void *user_data)
{
	wifi_handle_s *local_handle = (wifi_handle_s *)wifi;

	if(callback) {
		if(__wifi_get_callback_count(WIFI_DEVICE_STATE_CHANGED_CB) == 0)
			_wifi_libnet_set_device_state_changed_cb(
					__wifi_device_state_changed_cb, user_data);
	} else {
		if(__wifi_get_callback_count(WIFI_DEVICE_STATE_CHANGED_CB) == 1)
			_wifi_libnet_set_device_state_changed_cb(NULL, NULL);
	}

	local_handle->device_state_cb = callback;
	local_handle->device_state_user_data= user_data;
	return WIFI_ERROR_NONE;
}

static void __wifi_background_scan_cb(wifi_error_e error_code, void *user_data)
{
	GSList *list;

	for (list = wifi_handle_list; list; list = list->next) {
		wifi_handle_s *local_handle = (wifi_handle_s *)list->data;
		if (local_handle->bg_scan_cb)
			local_handle->bg_scan_cb(error_code, local_handle->bg_scan_user_data);
	}
}

static int __wifi_set_background_scan_cb(wifi_h wifi,
			void *callback, void *user_data)
{
	wifi_handle_s *local_handle = (wifi_handle_s *)wifi;

	if(callback) {
		if(__wifi_get_callback_count(WIFI_SCAN_FINISHED_CB) == 0)
			_wifi_libnet_set_background_scan_cb(
					__wifi_background_scan_cb, user_data);
	} else {
		if(__wifi_get_callback_count(WIFI_SCAN_FINISHED_CB) == 1)
			_wifi_libnet_set_background_scan_cb(NULL, NULL);
	}

	local_handle->bg_scan_cb = callback;
	local_handle->bg_scan_user_data= user_data;
	return WIFI_ERROR_NONE;
}

static void __wifi_connection_state_changed_cb(
			wifi_connection_state_e state, wifi_ap_h ap, void *user_data)
{
	GSList *list;

	for (list = wifi_handle_list; list; list = list->next) {
		wifi_handle_s *local_handle = (wifi_handle_s *)list->data;
		if (local_handle->connection_state_cb)
			local_handle->connection_state_cb(state, ap, local_handle->bg_scan_user_data);
	}
}

static int __wifi_set_connection_state_changed_cb(wifi_h wifi,
			void *callback, void *user_data)
{
	wifi_handle_s *local_handle = (wifi_handle_s *)wifi;

	if(callback) {
		if(__wifi_get_callback_count(WIFI_CONNECTION_STATE_CHANGED_CB) == 0)
			_wifi_libnet_set_connection_state_cb(
					__wifi_connection_state_changed_cb, user_data);
	} else {
		if(__wifi_get_callback_count(WIFI_CONNECTION_STATE_CHANGED_CB) == 1)
			_wifi_libnet_set_connection_state_cb(NULL, NULL);
	}

	local_handle->connection_state_cb= callback;
	local_handle->connection_state_user_data= user_data;
	return WIFI_ERROR_NONE;
}

static wifi_rssi_level_changed_cb
__wifi_get_rssi_level_changed_cb(wifi_handle_s *local_handle)
{
	return local_handle->rssi_level_changed_cb;
}

static void *__wifi_get_rssi_level_changed_userdata(
							wifi_handle_s *local_handle)
{
	return local_handle->rssi_level_changed_user_data;
}

static gboolean __wifi_rssi_level_changed_cb_idle(gpointer data)
{
	int rssi_level = 0;
	void *userdata;
	wifi_rssi_level_changed_cb callback;
	wifi_handle_s *local_handle = (wifi_handle_s *)data;

	if (__wifi_check_handle_validity((wifi_h)local_handle) != true)
		return FALSE;

	if (vconf_get_int(VCONFKEY_WIFI_STRENGTH, &rssi_level) != 0)
		return FALSE;

	callback = __wifi_get_rssi_level_changed_cb(local_handle);
	userdata = __wifi_get_rssi_level_changed_userdata(local_handle);

	if (callback)
		callback(rssi_level, userdata);

	return FALSE;
}

static void __wifi_rssi_level_changed_cb(keynode_t *node, void *user_data)
{
	GSList *list;
	wifi_h handle;

	if (_wifi_is_init() != true) {
		WIFI_LOG(WIFI_ERROR, "Application is not registered"
				"If multi-threaded, thread integrity be broken.");
		return;
	}

	for (list = wifi_handle_list; list; list = list->next) {
		handle = (wifi_h)list->data;
		_wifi_callback_add(__wifi_rssi_level_changed_cb_idle, (gpointer)handle);
	}
}

static int __wifi_set_rssi_level_changed_cb(wifi_h wifi,
			void *callback, void *user_data)
{
	static __thread gint refcount = 0;
	wifi_handle_s *local_handle;

	local_handle = (wifi_handle_s *)wifi;

	if (callback) {
		if (refcount == 0)
			vconf_notify_key_changed(VCONFKEY_WIFI_STRENGTH,
					__wifi_rssi_level_changed_cb, NULL);

		refcount++;
		WIFI_LOG(WIFI_INFO, "Successfully registered(%d)", refcount);
	} else {
		if (refcount > 0 &&
				__wifi_get_rssi_level_changed_cb(local_handle) != NULL) {
			if (--refcount == 0) {
				if (vconf_ignore_key_changed(VCONFKEY_WIFI_STRENGTH,
						__wifi_rssi_level_changed_cb) < 0) {
					WIFI_LOG(WIFI_ERROR, "Error to de-register vconf callback(%d)", refcount);
				} else {
					WIFI_LOG(WIFI_INFO, "Successfully de-registered(%d)", refcount);
				}
			}
		}
	}

	local_handle->rssi_level_changed_cb= callback;
	local_handle->rssi_level_changed_user_data= user_data;

	return WIFI_ERROR_NONE;
}

static int __wifi_get_handle_count(void)
{
	return ((int)g_slist_length(wifi_handle_list));
}

EXPORT_API int wifi_initialize(wifi_h *wifi)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (wifi == NULL || __wifi_check_handle_validity(*wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == true) {
		WIFI_LOG(WIFI_ERROR, "Already initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	*wifi = g_try_malloc0(sizeof(wifi_handle_s));
	if(*wifi != NULL)
		WIFI_LOG(WIFI_INFO, "New handle create[%p]", *wifi);
	else
		return WIFI_ERROR_OUT_OF_MEMORY;

	_wifi_dbus_init();

	rv = _wifi_libnet_init();
	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Init failed[%d]", rv);
		return WIFI_ERROR_OPERATION_FAILED;
	}

	wifi_handle_list = g_slist_prepend(wifi_handle_list, *wifi);

	WIFI_LOG(WIFI_INFO, "Wi-Fi successfully initialized");

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_deinitialize(wifi_h wifi)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	wifi_unset_rssi_level_changed_cb(wifi);

	WIFI_LOG(WIFI_INFO, "Destroy handle: %p", wifi);

	wifi_handle_list = g_slist_remove(wifi_handle_list, wifi);
	g_free(wifi);
	wifi = NULL;

	if (__wifi_get_handle_count() == 0) {
		if (_wifi_libnet_deinit() == false) {
			WIFI_LOG(WIFI_ERROR, "Deinit failed");
			return WIFI_ERROR_OPERATION_FAILED;
		}

		_wifi_callback_cleanup();
		_wifi_dbus_deinit();
	}

	WIFI_LOG(WIFI_INFO, "Wi-Fi successfully de-initialized");

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_activate(wifi_h wifi, wifi_activated_cb callback, void* user_data)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	rv = _wifi_activate(callback, FALSE, user_data);
	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR, "Failed to activate Wi-Fi[%d]", rv);

	return rv;
}

EXPORT_API int wifi_activate_with_wifi_picker_tested(
		wifi_h wifi, wifi_activated_cb callback, void* user_data)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	rv = _wifi_activate(callback, TRUE, user_data);
	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR, "Failed to activate Wi-Fi[%d]", rv);

	return rv;
}

EXPORT_API int wifi_deactivate(wifi_h wifi, wifi_deactivated_cb callback, void* user_data)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	rv = _wifi_deactivate(callback, user_data);
	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR, "Wi-Fi deactivation failed");

	return rv;
}

EXPORT_API int wifi_is_activated(wifi_h wifi, bool* activated)
{
	int rv;
	wifi_device_state_e device_state;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (activated == NULL || __wifi_check_handle_validity(wifi)) {
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

EXPORT_API int wifi_get_mac_address(wifi_h wifi, char** mac_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (mac_address == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

#if defined TIZEN_TV
	FILE *fp = NULL;
	char buf[WIFI_MAC_ADD_LENGTH + 1];
	if (0 == access(WIFI_MAC_ADD_PATH, F_OK))
		fp = fopen(WIFI_MAC_ADD_PATH, "r");

	if (fp == NULL) {
		WIFI_LOG(WIFI_ERROR, "Failed to open file"
				" %s\n", WIFI_MAC_ADD_PATH);
		return WIFI_ERROR_OPERATION_FAILED;
	}

	if (fgets(buf, sizeof(buf), fp) == NULL) {
		WIFI_LOG(WIFI_ERROR, "Failed to get MAC"
				" info from %s\n", WIFI_MAC_ADD_PATH);
		fclose(fp);
		return WIFI_ERROR_OPERATION_FAILED;
	}

	WIFI_LOG(WIFI_INFO, "%s : %s\n", WIFI_MAC_ADD_PATH, buf);

	*mac_address = (char *)g_try_malloc0(WIFI_MAC_ADD_LENGTH + 1);
	if (*mac_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "malloc() failed");
		fclose(fp);
		return WIFI_ERROR_OUT_OF_MEMORY;
	}
	g_strlcpy(*mac_address, buf, WIFI_MAC_ADD_LENGTH + 1);
	fclose(fp);
#else
	*mac_address = vconf_get_str(VCONFKEY_WIFI_BSSID_ADDRESS);

	if (*mac_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "Failed to get vconf"
			" from %s", VCONFKEY_WIFI_BSSID_ADDRESS);
		return WIFI_ERROR_OPERATION_FAILED;
	}
#endif

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_get_network_interface_name(wifi_h wifi, char** name)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (name == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_get_intf_name(name);
}

EXPORT_API int wifi_scan(wifi_h wifi, wifi_scan_finished_cb callback, void* user_data)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	rv = _wifi_libnet_scan_request(callback, user_data);
	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR, "Wi-Fi scan failed");

	return rv;
}

EXPORT_API int wifi_scan_specific_ap(wifi_h wifi,
		const char* essid, wifi_scan_finished_cb callback, void* user_data)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi) ||
		essid == NULL || callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");

		return WIFI_ERROR_INVALID_OPERATION;
	}

	rv = _wifi_libnet_scan_specific_ap(essid, callback, user_data);
	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR, "Wi-Fi hidden scan failed.\n");

	return rv;
}



EXPORT_API int wifi_get_connected_ap(wifi_h wifi, wifi_ap_h* ap)
{
	int rv;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (ap == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	rv = _wifi_libnet_get_connected_profile(ap);
	WIFI_LOG(WIFI_INFO, "Connected AP %p, rv %d", *ap, rv);

	return rv;
}

EXPORT_API int wifi_foreach_found_aps(wifi_h wifi,
		wifi_found_ap_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_foreach_found_aps(callback, user_data);
}

EXPORT_API int wifi_foreach_found_specific_aps(wifi_h wifi,
		wifi_found_ap_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_foreach_found_specific_aps(callback, user_data);
}

EXPORT_API int wifi_connect(wifi_h wifi,
		wifi_ap_h ap, wifi_connected_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_open_profile(ap, callback, user_data);
}

EXPORT_API int wifi_disconnect(wifi_h wifi,
		wifi_ap_h ap, wifi_disconnected_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_close_profile(ap, callback, user_data);
}

EXPORT_API int wifi_connect_by_wps_pbc(wifi_h wifi,
		wifi_ap_h ap, wifi_connected_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

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

EXPORT_API int wifi_connect_by_wps_pin(wifi_h wifi,
		wifi_ap_h ap, const char *pin, wifi_connected_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

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

EXPORT_API int wifi_forget_ap(wifi_h wifi, wifi_ap_h ap)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_forget_ap(ap);
}

EXPORT_API int wifi_get_connection_state(wifi_h wifi, wifi_connection_state_e* connection_state)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (connection_state == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return _wifi_libnet_get_wifi_state(connection_state);
}

EXPORT_API int wifi_set_device_state_changed_cb(wifi_h wifi,
		wifi_device_state_changed_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	return __wifi_set_device_state_changed_cb(wifi, callback, user_data);
}

EXPORT_API int wifi_unset_device_state_changed_cb(wifi_h wifi)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return __wifi_set_device_state_changed_cb(wifi, NULL, NULL);
}

EXPORT_API int wifi_set_background_scan_cb(wifi_h wifi,
		wifi_scan_finished_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL|| __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	return __wifi_set_background_scan_cb(wifi, callback, user_data);
}

EXPORT_API int wifi_unset_background_scan_cb(wifi_h wifi)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return __wifi_set_background_scan_cb(wifi, NULL, NULL);
}

EXPORT_API int wifi_set_connection_state_changed_cb(wifi_h wifi,
		wifi_connection_state_changed_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	return __wifi_set_connection_state_changed_cb(wifi, callback, user_data);
}

EXPORT_API int wifi_unset_connection_state_changed_cb(wifi_h wifi)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return __wifi_set_connection_state_changed_cb(wifi, NULL, NULL);
}

EXPORT_API int wifi_set_rssi_level_changed_cb(wifi_h wifi,
		wifi_rssi_level_changed_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (callback == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return __wifi_set_rssi_level_changed_cb(wifi, callback, user_data);
}

EXPORT_API int wifi_unset_rssi_level_changed_cb(wifi_h wifi)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return __wifi_set_rssi_level_changed_cb(wifi, NULL, NULL);
}

EXPORT_API int wifi_tdls_disconnect(wifi_h wifi, const char* peer_mac_addr)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (peer_mac_addr == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	int rv = 0;
	rv = net_wifi_tdls_disconnect(peer_mac_addr);

	if (rv != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Failed to disconnect tdls");
		return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_tdls_get_connected_peer(wifi_h wifi, char** peer_mac_addr)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (peer_mac_addr == NULL || __wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
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

EXPORT_API int wifi_tdls_set_state_changed_cb(wifi_h wifi, wifi_tdls_state_changed_cb callback, void* user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_tdls_unset_state_changed_cb(wifi_h wifi)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (__wifi_check_handle_validity(wifi)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}
