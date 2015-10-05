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
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "wifi_dbus_private.h"
#include "net_wifi_private.h"

static __thread bool is_init = false;
static __thread GSList *ap_handle_list = NULL;

struct _wifi_cb_s {
	wifi_device_state_changed_cb device_state_cb;
	void *device_state_user_data;
	wifi_scan_finished_cb bg_scan_cb;
	void *bg_scan_user_data;
	wifi_scan_finished_cb scan_request_cb;
	void *scan_request_user_data;
	wifi_scan_finished_cb specific_scan_cb;
	void *specific_scan_user_data;
	wifi_connection_state_changed_cb connection_state_cb;
	void *connection_state_user_data;
	wifi_activated_cb activated_cb;
	void *activated_user_data;
	wifi_deactivated_cb deactivated_cb;
	void *deactivated_user_data;
	wifi_connected_cb connected_cb;
	void *connected_user_data;
	wifi_disconnected_cb disconnected_cb;
	void *disconnected_user_data;
};

struct _profile_list_s {
	int count;
	net_profile_info_t *profiles;
};

struct _wifi_state_notify {
	net_profile_info_t *ap_info;
	wifi_connection_state_e state;
};

struct managed_idle_data {
	GSourceFunc func;
	gpointer user_data;
	guint id;
};

static __thread struct _wifi_cb_s wifi_callbacks = { 0, };
static __thread struct _profile_list_s profile_iterator = { 0, NULL };
static __thread struct _profile_list_s specific_profile_iterator = {0, NULL};
static __thread char specific_profile_essid[NET_WLAN_ESSID_LEN + 1] = { 0, };
static __thread bool is_feature_checked = false;
static __thread bool feature_supported = false;
static __thread GSList *managed_idler_list = NULL;

wifi_dbus *g_dbus_h = NULL;

bool _wifi_is_init(void)
{
	return is_init;
}

static void __wifi_set_init(bool tag)
{
	is_init = tag;
}

static wifi_error_e __libnet_convert_to_ap_error_type(net_err_t err_type)
{
	switch (err_type) {
	case NET_ERR_NONE:
		return WIFI_ERROR_NONE;
	case NET_ERR_APP_ALREADY_REGISTERED:
		return WIFI_ERROR_INVALID_OPERATION;
	case NET_ERR_APP_NOT_REGISTERED:
		return WIFI_ERROR_INVALID_OPERATION;
	case NET_ERR_NO_ACTIVE_CONNECTIONS:
		return WIFI_ERROR_NO_CONNECTION;
	case NET_ERR_ACTIVE_CONNECTION_EXISTS:
		return WIFI_ERROR_ALREADY_EXISTS;
	case NET_ERR_CONNECTION_DHCP_FAILED:
		return WIFI_ERROR_DHCP_FAILED;
	case NET_ERR_CONNECTION_INVALID_KEY:
		return WIFI_ERROR_INVALID_KEY;
	case NET_ERR_IN_PROGRESS:
		return WIFI_ERROR_NOW_IN_PROGRESS;
	case NET_ERR_OPERATION_ABORTED:
		return WIFI_ERROR_OPERATION_ABORTED;
	case NET_ERR_TIME_OUT:
		return WIFI_ERROR_NO_REPLY;
	case NET_ERR_ACCESS_DENIED:
		return WIFI_ERROR_PERMISSION_DENIED;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}
}

static const char *__libnet_convert_ap_error_type_to_string(wifi_error_e err_type)
{
	switch (err_type) {
	case WIFI_ERROR_NONE:
		return "NONE";
	case WIFI_ERROR_INVALID_PARAMETER:
		return "INVALID_PARAMETER";
	case WIFI_ERROR_OUT_OF_MEMORY:
		return "OUT_OF_MEMORY";
	case WIFI_ERROR_INVALID_OPERATION:
		return "INVALID_OPERATION";
	case WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED:
		return "ADDRESS_FAMILY_NOT_SUPPORTED";
	case WIFI_ERROR_OPERATION_FAILED:
		return "OPERATION_FAILED";
	case WIFI_ERROR_NO_CONNECTION:
		return "NO_CONNECTION";
	case WIFI_ERROR_NOW_IN_PROGRESS:
		return "NOW_IN_PROGRESS";
	case WIFI_ERROR_ALREADY_EXISTS:
		return "ALREADY_EXISTS";
	case WIFI_ERROR_OPERATION_ABORTED:
		return "OPERATION_ABORTED";
	case WIFI_ERROR_DHCP_FAILED:
		return "DHCP_FAILED";
	case WIFI_ERROR_INVALID_KEY:
		return "INVALID_KEY";
	case WIFI_ERROR_NO_REPLY:
		return "NO_REPLY";
	case WIFI_ERROR_SECURITY_RESTRICTED:
		return "SECURITY_RESTRICTED";
	case WIFI_ERROR_PERMISSION_DENIED:
		return "PERMISSION_DENIED";
	case WIFI_ERROR_NOT_SUPPORTED:
		return "NOT_SUPPROTED";
	}

	return "UNKNOWN";
}

static const char *__libnet_convert_ap_state_to_string(wifi_connection_state_e state)
{
	switch (state) {
	case WIFI_CONNECTION_STATE_FAILURE:
		return "FAILURE";
	case WIFI_CONNECTION_STATE_DISCONNECTED:
		return "DISCONNECTED";
	case WIFI_CONNECTION_STATE_ASSOCIATION:
		return "ASSOCIATION";
	case WIFI_CONNECTION_STATE_CONFIGURATION:
		return "CONFIGURATION";
	case WIFI_CONNECTION_STATE_CONNECTED:
		return "CONNECTED";
	default:
		return "UNKNOWN";
	}
}

static void __libnet_clear_profile_list(struct _profile_list_s *profile_list)
{
	if (profile_list->count > 0)
		g_free(profile_list->profiles);

	profile_list->count = 0;
	profile_list->profiles = NULL;
}

static int __libnet_update_profile_iterator(void)
{
	int rv;
	struct _profile_list_s wifi_profiles = { 0, NULL };

	__libnet_clear_profile_list(&profile_iterator);

	rv = net_get_profile_list(NET_DEVICE_WIFI, &wifi_profiles.profiles, &wifi_profiles.count);
	WIFI_LOG(WIFI_INFO, "Wi-Fi profile count: %d", wifi_profiles.count);

	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	}

	if (wifi_profiles.count == 0)
		return WIFI_ERROR_NONE;

	profile_iterator.count = wifi_profiles.count;
	profile_iterator.profiles = wifi_profiles.profiles;

	return WIFI_ERROR_NONE;
}

static void __libnet_update_specific_profile_iterator(GSList *ap_list)
{
    int count=0;
    GSList *list = ap_list;

    for (count = 0; list; list = list->next) {
		count++;
    }

	if (count == 0) {
		WIFI_LOG(WIFI_INFO, "No hidden AP found\n");
		return;
	}

	specific_profile_iterator.count = count;
	specific_profile_iterator.profiles = g_try_new0(net_profile_info_t, count);

	list = ap_list;
	for (count = 0; list; list = list->next) {
		struct ssid_scan_bss_info_t *ap = (struct ssid_scan_bss_info_t *)list->data;
		net_profile_info_t *profile = &specific_profile_iterator.profiles[count];

		g_strlcpy(profile->ProfileInfo.Wlan.essid, ap->ssid, NET_WLAN_ESSID_LEN+1);
		profile->ProfileInfo.Wlan.security_info.sec_mode = ap->security;

		count++;
	}

	WIFI_LOG(WIFI_INFO, "Specific AP count : %d\n", count);
}

static void __libnet_convert_profile_info_to_wifi_info(net_wifi_connection_info_t *wifi_info,
								net_profile_info_t *ap_info)
{
	g_strlcpy(wifi_info->essid, ap_info->ProfileInfo.Wlan.essid, NET_WLAN_ESSID_LEN+1);
	wifi_info->wlan_mode = ap_info->ProfileInfo.Wlan.wlan_mode;
	memcpy(&wifi_info->security_info, &ap_info->ProfileInfo.Wlan.security_info, sizeof(wlan_security_info_t));
	wifi_info->is_hidden = ap_info->ProfileInfo.Wlan.is_hidden;
}

static int __libnet_connect_with_wifi_info(net_profile_info_t *ap_info)
{
	int rv;
	net_wifi_connection_info_t wifi_info;
	memset(&wifi_info, 0, sizeof(net_wifi_connection_info_t));

	__libnet_convert_profile_info_to_wifi_info(&wifi_info, ap_info);

	rv = net_open_connection_with_wifi_info(&wifi_info);
	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

static gboolean __wifi_state_changed_cb(gpointer data)
{
	wifi_ap_h ap_info;
	struct _wifi_state_notify *notify = (struct _wifi_state_notify *)data;

	if (notify == NULL)
		return FALSE;

	if (notify->ap_info == NULL) {
		g_free(notify);
		return FALSE;
	}

	ap_info = (wifi_ap_h)notify->ap_info;

	_wifi_libnet_add_to_ap_list(ap_info);

	if (wifi_callbacks.connection_state_cb != NULL)
		wifi_callbacks.connection_state_cb(notify->state, ap_info,
						wifi_callbacks.connection_state_user_data);

	_wifi_libnet_remove_from_ap_list(ap_info);

	g_free(notify);

	return FALSE;
}

static void __libnet_state_changed_cb(char *profile_name, net_profile_info_t *profile_info,
							wifi_connection_state_e state)
{
	guint id;
	net_profile_info_t *ap_info = NULL;
	struct _wifi_state_notify *notify = NULL;

	if (_wifi_is_init() != true) {
		WIFI_LOG(WIFI_ERROR, "Application is not registered"
				"If multi-threaded, thread integrity be broken.");
		return;
	}

	if (wifi_callbacks.connection_state_cb == NULL)
		return;

	if (profile_name == NULL)
		return;

	if (profile_info == NULL) {
		SECURE_WIFI_LOG(WIFI_ERROR, "Failed to find: %s", profile_name);
		return;
	}

	ap_info = g_try_malloc0(sizeof(net_profile_info_t));
	if (ap_info == NULL) {
		WIFI_LOG(WIFI_ERROR, "Memory allocation error");
		return;
	}

	memcpy(ap_info, profile_info, sizeof(net_profile_info_t));

	notify = g_try_new0(struct _wifi_state_notify, 1);
	if (notify == NULL) {
		g_free(ap_info);
		return;
	}

	notify->ap_info = ap_info;
	notify->state = state;

	id = _wifi_callback_add(__wifi_state_changed_cb, (gpointer)notify);
	if (!id)
		g_free(notify);
}

static void __libnet_set_activated_cb(wifi_activated_cb user_cb, void *user_data)
{
	if (user_cb != NULL) {
		wifi_callbacks.activated_cb = user_cb;
		wifi_callbacks.activated_user_data = user_data;
	}
}

static gboolean __activated_cb_idle(gpointer data)
{
	wifi_error_e result = (wifi_error_e)data;

	if (wifi_callbacks.activated_cb != NULL)
		wifi_callbacks.activated_cb(result, wifi_callbacks.activated_user_data);

	wifi_callbacks.activated_cb = NULL;
	wifi_callbacks.activated_user_data = NULL;

	return FALSE;
}

static void __libnet_set_deactivated_cb(wifi_deactivated_cb user_cb, void *user_data)
{
	if (user_cb != NULL) {
		wifi_callbacks.deactivated_cb = user_cb;
		wifi_callbacks.deactivated_user_data = user_data;
	}
}

static gboolean __deactivated_cb_idle(gpointer data)
{
	wifi_error_e result = (wifi_error_e)data;

	if (wifi_callbacks.deactivated_cb != NULL)
		wifi_callbacks.deactivated_cb(result, wifi_callbacks.deactivated_user_data);

	wifi_callbacks.deactivated_cb = NULL;
	wifi_callbacks.deactivated_user_data = NULL;

	return FALSE;
}

static gboolean __device_state_cb_idle(gpointer data)
{
	wifi_device_state_e state = (wifi_device_state_e)data;

	if (wifi_callbacks.device_state_cb != NULL)
		wifi_callbacks.device_state_cb(state, wifi_callbacks.device_state_user_data);

	return FALSE;
}

static void __libnet_power_on_off_cb(net_event_info_t *event_cb, bool is_requested)
{
	if (_wifi_is_init() != true) {
		WIFI_LOG(WIFI_ERROR, "Application is not registered"
				"If multi-threaded, thread integrity be broken.");
		return;
	}

	if (wifi_callbacks.device_state_cb == NULL &&
			wifi_callbacks.activated_cb == NULL &&
			wifi_callbacks.deactivated_cb == NULL)
		return;

	wifi_error_e error_code = WIFI_ERROR_NONE;
	wifi_device_state_e state = WIFI_DEVICE_STATE_DEACTIVATED;
	net_wifi_state_t *wifi_state = (net_wifi_state_t *)event_cb->Data;

	if (event_cb->Error == NET_ERR_NONE &&
			event_cb->Datalength == sizeof(net_wifi_state_t)) {
		if (*wifi_state == WIFI_ON) {
			WIFI_LOG(WIFI_INFO, "Wi-Fi power on");
			state = WIFI_DEVICE_STATE_ACTIVATED;
		} else if (*wifi_state == WIFI_OFF) {
			WIFI_LOG(WIFI_INFO, "Wi-Fi power off");
			state = WIFI_DEVICE_STATE_DEACTIVATED;
			__libnet_clear_profile_list(&profile_iterator);
		} else {
			WIFI_LOG(WIFI_ERROR, "Error Wi-Fi state %d", *wifi_state);
			error_code = WIFI_ERROR_OPERATION_FAILED;
			state = WIFI_DEVICE_STATE_DEACTIVATED;
		}
	} else {
		WIFI_LOG(WIFI_ERROR, "Wi-Fi power request failed(%d)", event_cb->Error);

		if (event_cb->Error == NET_ERR_SECURITY_RESTRICTED)
			error_code = WIFI_ERROR_SECURITY_RESTRICTED;
		else
			error_code = WIFI_ERROR_OPERATION_FAILED;

		state = WIFI_DEVICE_STATE_DEACTIVATED;
	}

	if (wifi_callbacks.activated_cb != NULL)
		_wifi_callback_add(__activated_cb_idle, (gpointer)error_code);

	if (wifi_callbacks.deactivated_cb != NULL)
		_wifi_callback_add(__deactivated_cb_idle, (gpointer)error_code);

	if (wifi_callbacks.device_state_cb != NULL)
		_wifi_callback_add(__device_state_cb_idle, (gpointer)state);
}

static gboolean __scan_request_cb_idle(gpointer data)
{
	wifi_error_e error_code = (wifi_error_e)data;

	if (wifi_callbacks.scan_request_cb != NULL)
		wifi_callbacks.scan_request_cb(error_code, wifi_callbacks.scan_request_user_data);

	wifi_callbacks.scan_request_cb = NULL;
	wifi_callbacks.scan_request_user_data = NULL;

	return FALSE;
}

static void __libnet_set_specific_scan_cb(wifi_scan_finished_cb user_cb, void *user_data)
{
	if (user_cb != NULL) {
		wifi_callbacks.specific_scan_cb = user_cb;
		wifi_callbacks.specific_scan_user_data = user_data;
	}
}

static gboolean __specific_scan_cb_idle(gpointer data)
{
	wifi_error_e error_code = (wifi_error_e)data;

	if (wifi_callbacks.specific_scan_cb != NULL)
		wifi_callbacks.specific_scan_cb(error_code, wifi_callbacks.specific_scan_user_data);

	wifi_callbacks.specific_scan_cb = NULL;
	wifi_callbacks.specific_scan_user_data = NULL;

	return FALSE;
}

static gboolean __bgscan_cb_idle(gpointer data)
{
	wifi_error_e error_code = (wifi_error_e)data;

	if (wifi_callbacks.bg_scan_cb != NULL)
		wifi_callbacks.bg_scan_cb(error_code, wifi_callbacks.bg_scan_user_data);

	return FALSE;
}

static void __libnet_scan_cb(net_event_info_t *event_cb, bool is_requested)
{
	wifi_error_e error_code = WIFI_ERROR_NONE;

	if (_wifi_is_init() != true) {
		WIFI_LOG(WIFI_ERROR, "Application is not registered"
				"If multi-threaded, thread integrity be broken.");
		return;
	}

	if (event_cb->Error != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Scan failed[%d]", event_cb->Error);
		error_code = WIFI_ERROR_OPERATION_FAILED;
	}

	if (wifi_callbacks.scan_request_cb != NULL) {
		_wifi_callback_add(__scan_request_cb_idle, (gpointer)error_code);
		return;
	}

	if (wifi_callbacks.bg_scan_cb != NULL)
		_wifi_callback_add(__bgscan_cb_idle, (gpointer)error_code);
}

static void __libnet_specific_scan_cb(net_event_info_t *event_cb)
{
	wifi_error_e error_code = WIFI_ERROR_NONE;

	__libnet_clear_profile_list(&specific_profile_iterator);

	if (event_cb->Error != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Specific scan failed!, Error [%d]\n", event_cb->Error);
		error_code = WIFI_ERROR_OPERATION_FAILED;
	} else if (event_cb->Data) {
		GSList *ap_list = (GSList *)event_cb->Data;
		__libnet_update_specific_profile_iterator(ap_list);
	}

	if (wifi_callbacks.specific_scan_cb != NULL)
		_wifi_callback_add(__specific_scan_cb_idle, (gpointer)error_code);
}

static void __libnet_set_connected_cb(wifi_connected_cb user_cb, void *user_data)
{
	if (user_cb != NULL) {
		wifi_callbacks.connected_cb = user_cb;
		wifi_callbacks.connected_user_data = user_data;
	}
}

static gboolean __connected_cb_idle(gpointer data)
{
	wifi_error_e result = (wifi_error_e)data;

	if (wifi_callbacks.connected_cb != NULL)
		wifi_callbacks.connected_cb(result, wifi_callbacks.connected_user_data);

	wifi_callbacks.connected_cb = NULL;
	wifi_callbacks.connected_user_data = NULL;

	return FALSE;
}

static void __libnet_connected_cb(wifi_error_e result)
{
	if (_wifi_is_init() != true) {
		WIFI_LOG(WIFI_ERROR, "Application is not registered"
				"If multi-threaded, thread integrity be broken.");
		return;
	}

	if (wifi_callbacks.connected_cb != NULL)
		_wifi_callback_add(__connected_cb_idle, (gpointer)result);
}

static void __libnet_set_disconnected_cb(wifi_disconnected_cb user_cb, void *user_data)
{
	if (user_cb != NULL) {
		wifi_callbacks.disconnected_cb = user_cb;
		wifi_callbacks.disconnected_user_data = user_data;
	}
}

static gboolean __disconnected_cb_idle(gpointer data)
{
	wifi_error_e result = (wifi_error_e)data;

	if (wifi_callbacks.disconnected_cb != NULL)
		wifi_callbacks.disconnected_cb(result, wifi_callbacks.disconnected_user_data);

	wifi_callbacks.disconnected_cb = NULL;
	wifi_callbacks.disconnected_user_data = NULL;

	return FALSE;
}

static void __libnet_disconnected_cb(wifi_error_e result)
{
	if (_wifi_is_init() != true) {
		WIFI_LOG(WIFI_ERROR, "Application is not registered"
				"If multi-threaded, thread integrity be broken.");
		return;
	}

	if (wifi_callbacks.disconnected_cb != NULL)
		_wifi_callback_add(__disconnected_cb_idle, (gpointer)result);
}

static void __libnet_evt_cb(net_event_info_t *event_cb, void *user_data)
{
	bool is_requested = false;
	net_profile_info_t *prof_info_p = NULL;
	net_profile_info_t prof_info;
	wifi_error_e result = WIFI_ERROR_NONE;
	int i = 0;
	bool is_profile_exists = false;

	switch (event_cb->Event) {
	case NET_EVENT_OPEN_RSP:
	case NET_EVENT_WIFI_WPS_RSP:
		is_requested = true;
		/* fall through */
	case NET_EVENT_OPEN_IND:
		if (_wifi_libnet_check_profile_name_validity(event_cb->ProfileName) != true)
			return;

		result = __libnet_convert_to_ap_error_type(event_cb->Error);
		WIFI_LOG(WIFI_INFO, "Connection open error %s",
				__libnet_convert_ap_error_type_to_string(result));

		if (is_requested)
			__libnet_connected_cb(result);

		switch (event_cb->Error) {
		case NET_ERR_NONE:
			if (event_cb->Datalength == sizeof(net_profile_info_t))
				prof_info_p = (net_profile_info_t *)event_cb->Data;

			__libnet_state_changed_cb(event_cb->ProfileName, prof_info_p,
							WIFI_CONNECTION_STATE_CONNECTED);
			return;
		case NET_ERR_ACTIVE_CONNECTION_EXISTS:
			return;
		default :
			break;
		}

		if (net_get_profile_info(event_cb->ProfileName, &prof_info) == NET_ERR_NONE)
			__libnet_state_changed_cb(event_cb->ProfileName, &prof_info,
						WIFI_CONNECTION_STATE_DISCONNECTED);
		else
			__libnet_state_changed_cb(event_cb->ProfileName, NULL,
						WIFI_CONNECTION_STATE_DISCONNECTED);

		break;
	case NET_EVENT_CLOSE_RSP:
		is_requested = true;
		/* fall through */
	case NET_EVENT_CLOSE_IND:
		if (_wifi_libnet_check_profile_name_validity(event_cb->ProfileName) != true)
			return;

		result = __libnet_convert_to_ap_error_type(event_cb->Error);
		WIFI_LOG(WIFI_ERROR, "Connection close error %s",
				__libnet_convert_ap_error_type_to_string(result));

		if (is_requested)
			__libnet_disconnected_cb(result);

		switch (event_cb->Error) {
		case NET_ERR_NONE:
			if (net_get_profile_info(event_cb->ProfileName, &prof_info) == NET_ERR_NONE)
				__libnet_state_changed_cb(event_cb->ProfileName, &prof_info,
						WIFI_CONNECTION_STATE_DISCONNECTED);
			else
				__libnet_state_changed_cb(event_cb->ProfileName, NULL,
						WIFI_CONNECTION_STATE_DISCONNECTED);
			return;
		default:
			break;
		}

		break;
	case NET_EVENT_NET_STATE_IND:
		if (_wifi_libnet_check_profile_name_validity(event_cb->ProfileName) != true)
			return;

		if (event_cb->Datalength != sizeof(net_state_type_t))
			return;

		net_state_type_t *profile_state = (net_state_type_t *)event_cb->Data;
		wifi_connection_state_e ap_state = _wifi_convert_to_ap_state(*profile_state);

		WIFI_LOG(WIFI_INFO, "state: %s", __libnet_convert_ap_state_to_string(ap_state));
		SECURE_WIFI_LOG(WIFI_INFO, "profile name: %s", event_cb->ProfileName);

		if (net_get_profile_info(event_cb->ProfileName, &prof_info) == NET_ERR_NONE)
			__libnet_state_changed_cb(event_cb->ProfileName, &prof_info, ap_state);
		else if (ap_state == WIFI_CONNECTION_STATE_DISCONNECTED) {
			for (i = 0; i < profile_iterator.count; i++) {
				if (!g_strcmp0(event_cb->ProfileName,
						profile_iterator.profiles[i].ProfileName)) {
					is_profile_exists = true;
					break;
				}
			}

			if (is_profile_exists == true) {
				profile_iterator.profiles[i].ProfileState = *profile_state;
				__libnet_state_changed_cb(event_cb->ProfileName,
							&profile_iterator.profiles[i], ap_state);
			} else
				__libnet_state_changed_cb(event_cb->ProfileName,
							NULL, ap_state);
		} else
			__libnet_state_changed_cb(event_cb->ProfileName, NULL, ap_state);

		break;
	case NET_EVENT_WIFI_SCAN_RSP:
	case NET_EVENT_WIFI_SCAN_IND:
		__libnet_scan_cb(event_cb, is_requested);
		break;
	case NET_EVENT_SPECIFIC_SCAN_RSP:
		WIFI_LOG(WIFI_INFO, "Got Wi-Fi specific scan RSP\n");
		break;
	case NET_EVENT_SPECIFIC_SCAN_IND:
		WIFI_LOG(WIFI_INFO, "Got Wi-Fi specific scan IND\n");
		__libnet_specific_scan_cb(event_cb);
		break;
	case NET_EVENT_WIFI_POWER_RSP:
		is_requested = true;
		/* fall through */
	case NET_EVENT_WIFI_POWER_IND:
		__libnet_power_on_off_cb(event_cb, is_requested);
		break;
	default :
		break;
	}
}

int _wifi_libnet_init(void)
{
	int rv;

	rv = net_register_client_ext((net_event_cb_t)__libnet_evt_cb, NET_DEVICE_WIFI, NULL);
	if (rv != NET_ERR_NONE)
		return rv;

	__wifi_set_init(true);

	return NET_ERR_NONE;
}

bool _wifi_libnet_deinit(void)
{
	if (net_deregister_client_ext(NET_DEVICE_WIFI) != NET_ERR_NONE)
		return false;

	__libnet_clear_profile_list(&profile_iterator);
	g_slist_free_full(ap_handle_list, g_free);
	ap_handle_list = NULL;
	memset(&wifi_callbacks, 0, sizeof(struct _wifi_cb_s));

	__wifi_set_init(false);

	return true;
}

int _wifi_activate(wifi_activated_cb callback, gboolean wifi_picker_test,
					void *user_data)
{
	int rv = NET_ERR_NONE;

	rv = net_wifi_power_on(wifi_picker_test);
	if (rv == NET_ERR_NONE) {
		__libnet_set_activated_cb(callback, user_data);
		return WIFI_ERROR_NONE;
	} else if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;
	else if (rv == NET_ERR_ALREADY_EXISTS)
		return WIFI_ERROR_ALREADY_EXISTS;
	else if (rv == NET_ERR_IN_PROGRESS)
		return WIFI_ERROR_NOW_IN_PROGRESS;
	else if (rv == NET_ERR_SECURITY_RESTRICTED)
		return WIFI_ERROR_SECURITY_RESTRICTED;

	return WIFI_ERROR_OPERATION_FAILED;
}

int _wifi_deactivate(wifi_deactivated_cb callback, void *user_data)
{
	int rv = NET_ERR_NONE;

	rv = net_wifi_power_off();
	if (rv == NET_ERR_NONE) {
		__libnet_set_deactivated_cb(callback, user_data);
		return WIFI_ERROR_NONE;
	} else if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;
	else if (rv == NET_ERR_ALREADY_EXISTS)
		return WIFI_ERROR_ALREADY_EXISTS;
	else if (rv == NET_ERR_IN_PROGRESS)
		return WIFI_ERROR_NOW_IN_PROGRESS;
	else if (rv == NET_ERR_SECURITY_RESTRICTED)
		return WIFI_ERROR_SECURITY_RESTRICTED;

	return WIFI_ERROR_OPERATION_FAILED;
}

bool _wifi_libnet_check_ap_validity(wifi_ap_h ap_h)
{
	int i;
	GSList *list = NULL;

	if (ap_h == NULL)
		return false;

	for (list = ap_handle_list; list; list = list->next)
		if (ap_h == list->data) return true;

	for (i = 0; i < profile_iterator.count; i++)
		if (ap_h == &profile_iterator.profiles[i]) return true;

	for (i = 0; i < specific_profile_iterator.count; i++)
		if (ap_h == &specific_profile_iterator.profiles[i]) return true;

	return false;
}

void _wifi_libnet_add_to_ap_list(wifi_ap_h ap_h)
{
	ap_handle_list = g_slist_append(ap_handle_list, ap_h);
}

void _wifi_libnet_remove_from_ap_list(wifi_ap_h ap_h)
{
	ap_handle_list = g_slist_remove(ap_handle_list, ap_h);
	g_free(ap_h);
}

bool _wifi_libnet_check_profile_name_validity(const char *profile_name)
{
	const char *profile_prefix = "/net/connman/service/wifi_";
	int i = 0;

	if (profile_name == NULL ||
			g_str_has_prefix(profile_name, profile_prefix) != TRUE) {
		WIFI_LOG(WIFI_INFO, "The profile is a hidden or not a regular Wi-Fi profile");
		return false;
	}

	while (profile_name[i] != '\0') {
		if (isgraph(profile_name[i]) == 0) {
			WIFI_LOG(WIFI_INFO, "Invalid format: %s", profile_name);
			return false;
		}
		i++;
	}

	return true;
}

int _wifi_libnet_get_wifi_device_state(wifi_device_state_e *device_state)
{
	net_tech_info_t tech_info;

	int rv = NET_ERR_NONE;
	rv = net_get_technology_properties(NET_DEVICE_WIFI, &tech_info);
	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Failed to get technology properties");
		return WIFI_ERROR_OPERATION_FAILED;
	}

	if (tech_info.powered)
		*device_state = WIFI_DEVICE_STATE_ACTIVATED;
	else
		*device_state = WIFI_DEVICE_STATE_DEACTIVATED;

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_get_wifi_state(wifi_connection_state_e *connection_state)
{
	wifi_dbus *dbus_h = NULL;
	GError *error = NULL;
	GVariant *result = NULL;
	gint state = 0;

	dbus_h = _wifi_get_dbus_handle();
	if (dbus_h == NULL) {
		WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	result = g_dbus_connection_call_sync(dbus_h->dbus_conn,
					     NETCONFIG_SERVICE,
					     NETCONFIG_WIFI_PATH,
					     NETCONFIG_IWIFI,
					     "GetWifiState",
					     g_variant_new("()"),
					     NULL, G_DBUS_CALL_FLAGS_NONE,
					     DBUS_REPLY_TIMEOUT, dbus_h->ca,
					     &error);

	if (error) {
		WIFI_LOG(WIFI_ERROR, "Fail to GetWifiState [%d: %s]", error->code, error->message);
		g_error_free(error);
		return WIFI_ERROR_OPERATION_FAILED;
	}

	if (result != NULL) {
		g_variant_get(result, "(i)", &state);
		g_variant_unref(result);
	}

	*connection_state = state;

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_get_intf_name(char** name)
{
	int rv;

	if (profile_iterator.count == 0) {
		rv = __libnet_update_profile_iterator();
		if (rv == NET_ERR_ACCESS_DENIED) {
			WIFI_LOG(WIFI_ERROR, "Access denied");
			return WIFI_ERROR_PERMISSION_DENIED;
		}
	}

	if (profile_iterator.count == 0) {
		WIFI_LOG(WIFI_ERROR, "There is no AP");
		return WIFI_ERROR_OPERATION_FAILED;
	}

	*name = g_strdup(profile_iterator.profiles->ProfileInfo.Wlan.net_info.DevName);
	if (*name == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_scan_request(wifi_scan_finished_cb callback, void *user_data)
{
	int rv;
	rv = net_scan_wifi();

	if (rv == NET_ERR_NONE) {
		wifi_callbacks.scan_request_cb = callback;
		wifi_callbacks.scan_request_user_data = user_data;
		return WIFI_ERROR_NONE;
	} else if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;

	return WIFI_ERROR_OPERATION_FAILED;
}

int _wifi_libnet_scan_specific_ap(const char *essid,
                                       wifi_scan_finished_cb callback, void *user_data)
{
	int rv;
    rv = net_specific_scan_wifi(essid);

    if (rv == NET_ERR_NONE) {
		g_strlcpy(specific_profile_essid, essid, NET_WLAN_ESSID_LEN+1);
		__libnet_set_specific_scan_cb(callback, user_data);
		return WIFI_ERROR_NONE;
	} else if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;

	return WIFI_ERROR_OPERATION_FAILED;
}

int _wifi_libnet_get_connected_profile(wifi_ap_h *ap)
{
	int i, rv;
	wifi_ap_h ap_h = NULL;

	rv = __libnet_update_profile_iterator();
	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	}

	for (i = 0; i < profile_iterator.count; i++) {
		if (profile_iterator.profiles[i].ProfileState == NET_STATE_TYPE_ONLINE ||
		    profile_iterator.profiles[i].ProfileState == NET_STATE_TYPE_READY) {
			ap_h = (wifi_ap_h)(&profile_iterator.profiles[i]);
			break;
		}
	}

	if (ap_h == NULL) {
		WIFI_LOG(WIFI_ERROR, "There is no connected AP");
		return WIFI_ERROR_NO_CONNECTION;
	}

	*ap = g_try_malloc0(sizeof(net_profile_info_t));
	if (*ap == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	memcpy(*ap, ap_h, sizeof(net_profile_info_t));

	_wifi_libnet_add_to_ap_list(*ap);

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_foreach_found_aps(wifi_found_ap_cb callback, void *user_data)
{
	int i, rv;

	rv = __libnet_update_profile_iterator();
	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	}

	if (profile_iterator.count == 0) {
		WIFI_LOG(WIFI_WARN, "There is no AP");
		return WIFI_ERROR_NONE;
	}

	for (i = 0; i < profile_iterator.count; i++) {
		if (profile_iterator.profiles[i].ProfileInfo.Wlan.is_hidden == TRUE)
			continue;

		rv = callback((wifi_ap_h)(&profile_iterator.profiles[i]), user_data);
		if (rv == false) break;
	}

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_foreach_found_specific_aps(wifi_found_ap_cb callback, void *user_data)
{
	int i, rv;

	if (specific_profile_iterator.count == 0) {
		WIFI_LOG(WIFI_WARN, "There is no specific APs");

		rv = __libnet_update_profile_iterator();
		if (rv == NET_ERR_ACCESS_DENIED) {
			WIFI_LOG(WIFI_ERROR, "Access denied");
			return WIFI_ERROR_PERMISSION_DENIED;
		}

		if (profile_iterator.count == 0) {
			WIFI_LOG(WIFI_WARN, "There is no APs");
			return WIFI_ERROR_NONE;
		}

		for (i = 0; i < profile_iterator.count; i++) {
			if (!g_strcmp0(specific_profile_essid,
						profile_iterator.profiles[i].ProfileInfo.Wlan.essid)) {
				rv = callback((wifi_ap_h)(&profile_iterator.profiles[i]), user_data);
				if (rv == false) break;
			}
		}
		return WIFI_ERROR_NONE;
	}

	for (i = 0; i < specific_profile_iterator.count; i++) {
		rv = callback((wifi_ap_h)(&specific_profile_iterator.profiles[i]), user_data);
		if (rv == false) break;
	}

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_open_profile(wifi_ap_h ap_h, wifi_connected_cb callback, void *user_data)
{
	int rv;
	bool valid_profile;
	net_profile_info_t *ap_info = ap_h;

	valid_profile =
			_wifi_libnet_check_profile_name_validity(ap_info->ProfileName);

	if (valid_profile == true && ap_info->Favourite)
		rv = net_open_connection_with_profile(ap_info->ProfileName);
	else if (valid_profile == true &&
			ap_info->ProfileInfo.Wlan.is_hidden != TRUE &&
			ap_info->ProfileInfo.Wlan.security_info.sec_mode ==
												WLAN_SEC_MODE_NONE)
		rv = net_open_connection_with_profile(ap_info->ProfileName);
	else
		rv = __libnet_connect_with_wifi_info(ap_info);

	rv = __libnet_convert_to_ap_error_type(rv);
	if (rv == WIFI_ERROR_NONE)
		__libnet_set_connected_cb(callback, user_data);

	return rv;
}

int _wifi_libnet_close_profile(wifi_ap_h ap_h, wifi_disconnected_cb callback, void *user_data)
{
	int rv;
	net_profile_info_t *ap_info = ap_h;

	rv = net_close_connection(ap_info->ProfileName);
	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	__libnet_set_disconnected_cb(callback, user_data);

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_connect_with_wps_pbc(wifi_ap_h ap_h, wifi_connected_cb callback, void *user_data)
{
	int rv;
	net_profile_info_t *ap_info = ap_h;
	net_wifi_wps_info_t wps_info;
	memset(&wps_info, 0, sizeof(net_wifi_wps_info_t));

	wps_info.type = WIFI_WPS_PBC;

	rv = net_wifi_enroll_wps(ap_info->ProfileName, &wps_info);
	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	__libnet_set_connected_cb(callback, user_data);

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_connect_with_wps_pin(wifi_ap_h ap_h, const char *pin,
		wifi_connected_cb callback, void *user_data)
{
	int rv;
	net_profile_info_t *ap_info = ap_h;
	net_wifi_wps_info_t wps_info;

	if (ap_info == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	wps_info.type = WIFI_WPS_PIN;
	g_strlcpy(wps_info.pin, pin, NET_WLAN_MAX_WPSPIN_LEN + 1);

	rv = net_wifi_enroll_wps(ap_info->ProfileName, &wps_info);
	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	__libnet_set_connected_cb(callback, user_data);

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_forget_ap(wifi_ap_h ap)
{
	int rv = 0;
	net_profile_info_t *ap_info = ap;

	if (ap_info == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	rv = net_delete_profile(ap_info->ProfileName);
	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	ap_info->Favourite = (char)FALSE;

	return WIFI_ERROR_NONE;
}

int _wifi_set_power_on_off_cb(wifi_device_state_changed_cb callback, void *user_data)
{
	if (wifi_callbacks.device_state_cb != NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.device_state_cb = callback;
	wifi_callbacks.device_state_user_data = user_data;

	WIFI_LOG(WIFI_INFO, "Wi-Fi registered device state changed callback");

	return WIFI_ERROR_NONE;
}

int _wifi_unset_power_on_off_cb(void)
{
	if (wifi_callbacks.device_state_cb == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.device_state_cb = NULL;
	wifi_callbacks.device_state_user_data = NULL;

	return WIFI_ERROR_NONE;
}

int _wifi_set_background_scan_cb(wifi_scan_finished_cb callback, void *user_data)
{
	if (wifi_callbacks.bg_scan_cb != NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.bg_scan_cb = callback;
	wifi_callbacks.bg_scan_user_data = user_data;

	return WIFI_ERROR_NONE;
}

int _wifi_unset_background_scan_cb(void)
{
	if (wifi_callbacks.bg_scan_cb == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.bg_scan_cb = NULL;
	wifi_callbacks.bg_scan_user_data = NULL;

	return WIFI_ERROR_NONE;
}

int _wifi_set_connection_state_cb(wifi_connection_state_changed_cb callback, void *user_data)
{
	if (wifi_callbacks.connection_state_cb != NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.connection_state_cb = callback;
	wifi_callbacks.connection_state_user_data = user_data;

	return WIFI_ERROR_NONE;
}

int _wifi_unset_connection_state_cb()
{
	if (wifi_callbacks.connection_state_cb == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.connection_state_cb = NULL;
	wifi_callbacks.connection_state_user_data = NULL;

	return WIFI_ERROR_NONE;
}

int _wifi_update_ap_info(net_profile_info_t *ap_info)
{
	int rv = NET_ERR_NONE;
	rv = net_modify_profile(ap_info->ProfileName, ap_info);

	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied");
		return WIFI_ERROR_PERMISSION_DENIED;
	} else if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

static void __wifi_idle_destroy_cb(gpointer data)
{
	if (!data)
		return;

	managed_idler_list = g_slist_remove(managed_idler_list, data);
	g_free(data);
}

static gboolean __wifi_idle_cb(gpointer user_data)
{
	struct managed_idle_data *data = (struct managed_idle_data *)user_data;

	if (!data)
		return FALSE;

	return data->func(data->user_data);
}

guint _wifi_callback_add(GSourceFunc func, gpointer user_data)
{
	guint id;
	struct managed_idle_data *data;

	if (!func)
		return 0;

	data = g_try_new0(struct managed_idle_data, 1);
	if (!data)
		return 0;

	data->func = func;
	data->user_data = user_data;

	id = g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, __wifi_idle_cb, data,
			__wifi_idle_destroy_cb);
	if (!id) {
		g_free(data);
		return id;
	}

	data->id = id;

	managed_idler_list = g_slist_append(managed_idler_list, data);

	return id;
}

void _wifi_callback_cleanup(void)
{
	GSList *cur = managed_idler_list;
	GSource *src;
	struct managed_idle_data *data;

	while (cur) {
		GSList *next = cur->next;
		data = (struct managed_idle_data *)cur->data;

		src = g_main_context_find_source_by_id(g_main_context_default(), data->id);
		if (src) {
			g_source_destroy(src);
			cur = managed_idler_list;
		} else
			cur = next;
	}

	g_slist_free(managed_idler_list);
	managed_idler_list = NULL;
}

int _wifi_check_feature_supported(const char *feature_name)
{
	if(is_feature_checked) {
		if(!feature_supported) {
			LOGE("%s feature is disabled", feature_name);
			return WIFI_ERROR_NOT_SUPPORTED;
		}
	}
	else {
		if (!system_info_get_platform_bool(feature_name, &feature_supported)) {
			is_feature_checked = true;
			if (!feature_supported) {
				LOGE("%s feature is disabled", feature_name);
				return WIFI_ERROR_NOT_SUPPORTED;
			}
		}
		else {
			LOGE("Error - Feature getting from System Info");
			return WIFI_ERROR_OPERATION_FAILED;
		}
	}

	return WIFI_ERROR_NONE;
}

int _wifi_dbus_init(void)
{
	int rv;

	rv = wifi_dbus_init(&g_dbus_h);
	if (rv != NET_ERR_NONE)
		return rv;

	return NET_ERR_NONE;
}

int _wifi_dbus_deinit(void)
{
	wifi_dbus_deinit(g_dbus_h);
	g_dbus_h = NULL;

	return NET_ERR_NONE;
}

wifi_dbus *_wifi_get_dbus_handle(void)
{
	if (g_dbus_h == NULL) {
		WIFI_LOG(WIFI_ERROR, "g_dbus_h is NULL");
		return NULL;
	}

	return g_dbus_h;
}
