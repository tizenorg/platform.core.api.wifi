/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include "net_wifi_private.h"

static GSList *ap_handle_list = NULL;

struct _wifi_cb_s {
	wifi_device_state_changed_cb device_state_cb;
	void *device_state_user_data;
	wifi_scan_finished_cb bg_scan_cb;
	void *bg_scan_user_data;
	wifi_scan_finished_cb scan_request_cb;
	void *scan_request_user_data;
	wifi_connection_state_changed_cb connection_state_cb;
	void *connection_state_user_data;
};

struct _profile_list_s {
	int count;
	net_profile_info_t *profiles;
};

static struct _wifi_cb_s wifi_callbacks = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
static struct _profile_list_s profile_iterator = {0, NULL};


static void __libnet_clear_profile_list(struct _profile_list_s *profile_list)
{
	if (profile_list->count > 0)
		g_free(profile_list->profiles);

	profile_list->count = 0;
	profile_list->profiles = NULL;
}

static void __libnet_update_profile_iterator(void)
{
	struct _profile_list_s wifi_profiles = {0, NULL};

	__libnet_clear_profile_list(&profile_iterator);

	net_get_profile_list(NET_DEVICE_WIFI, &wifi_profiles.profiles, &wifi_profiles.count);
	WIFI_LOG(WIFI_INFO, "Wifi profile count : %d\n", wifi_profiles.count);

	if (wifi_profiles.count == 0)
		return;

	profile_iterator.count = wifi_profiles.count;
	profile_iterator.profiles = wifi_profiles.profiles;
}

static void __libnet_convert_profile_info_to_wifi_info(net_wifi_connection_info_t *wifi_info,
								net_profile_info_t *ap_info)
{
	g_strlcpy(wifi_info->essid, ap_info->ProfileInfo.Wlan.essid, NET_WLAN_ESSID_LEN+1);
	wifi_info->wlan_mode = ap_info->ProfileInfo.Wlan.wlan_mode;
	memcpy(&wifi_info->security_info, &ap_info->ProfileInfo.Wlan.security_info, sizeof(wlan_security_info_t));
}

static int __libnet_connect_with_wifi_info(net_profile_info_t *ap_info)
{
	net_wifi_connection_info_t wifi_info;
	memset(&wifi_info, 0, sizeof(net_wifi_connection_info_t));

	__libnet_convert_profile_info_to_wifi_info(&wifi_info, ap_info);

	if (net_open_connection_with_wifi_info(&wifi_info) != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

static void __libnet_state_changed_cb(char *profile_name, net_profile_info_t *profile_info,
		wifi_error_e error, wifi_connection_state_e state, bool is_requested)
{
	if (profile_name == NULL)
		return;

	if (profile_info == NULL) {
		WIFI_LOG(WIFI_ERROR, "Error!! Profile info not found! : %s\n", profile_name);
		return;
	}

	ap_handle_list = g_slist_append(ap_handle_list, (wifi_ap_h)profile_info);

	if (wifi_callbacks.connection_state_cb)
		wifi_callbacks.connection_state_cb(error, state, (wifi_ap_h)profile_info,
				is_requested, wifi_callbacks.connection_state_user_data);

	ap_handle_list = g_slist_remove(ap_handle_list, (wifi_ap_h)profile_info);
}

static void __libnet_power_on_off_cb(net_event_info_t *event_cb, bool is_requested)
{
	if (wifi_callbacks.device_state_cb == NULL)
		return;

	wifi_error_e error_code = WIFI_ERROR_NONE;
	wifi_device_state_e state;
	net_wifi_state_t *wifi_state = (net_wifi_state_t*)event_cb->Data;

	if (event_cb->Error == NET_ERR_NONE &&
	    event_cb->Datalength == sizeof(net_wifi_state_t)) {

		if (*wifi_state == WIFI_ON) {
			WIFI_LOG(WIFI_INFO, "Wi-Fi State : Power ON\n");
			state = WIFI_DEVICE_STATE_ACTIVATED;
		} else if (*wifi_state == WIFI_OFF) {
			WIFI_LOG(WIFI_INFO, "Wi-Fi State : Power OFF\n");
			state = WIFI_DEVICE_STATE_DEACTIVATED;
		} else {
			WIFI_LOG(WIFI_INFO, "Wi-Fi State : Unknown\n");
			error_code = WIFI_ERROR_OPERATION_FAILED;
			state = WIFI_DEVICE_STATE_DEACTIVATED;
		}
	} else {
		WIFI_LOG(WIFI_ERROR, "Wi-Fi Power on/off request failed! Error [%d]\n", event_cb->Error);
		error_code = WIFI_ERROR_OPERATION_FAILED;
		state = WIFI_DEVICE_STATE_DEACTIVATED;
	}

	wifi_callbacks.device_state_cb(error_code, state, is_requested, wifi_callbacks.device_state_user_data);
}

static void __libnet_scan_cb(net_event_info_t *event_cb, bool is_requested)
{
	wifi_error_e error_code = WIFI_ERROR_NONE;

	if (event_cb->Error != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Scan failed!, Error [%d]\n", event_cb->Error);
		error_code = WIFI_ERROR_OPERATION_FAILED;
	}

	if (wifi_callbacks.scan_request_cb) {
		wifi_callbacks.scan_request_cb(error_code, wifi_callbacks.scan_request_user_data);
		wifi_callbacks.scan_request_cb = NULL;
		wifi_callbacks.scan_request_user_data = NULL;
		return;
	}

	if (wifi_callbacks.bg_scan_cb != NULL)
		wifi_callbacks.bg_scan_cb(error_code, wifi_callbacks.bg_scan_user_data);
}

static void __libnet_evt_cb(net_event_info_t *event_cb, void *user_data)
{
	bool is_requested = false;
	net_profile_info_t *prof_info_p = NULL;
	net_profile_info_t prof_info;

	switch (event_cb->Event) {
	case NET_EVENT_OPEN_RSP:
	case NET_EVENT_WIFI_WPS_RSP:
		is_requested = true;
	case NET_EVENT_OPEN_IND:
		if (strstr(event_cb->ProfileName, "/wifi_") == NULL) return;

		WIFI_LOG(WIFI_INFO,
			"Received ACTIVATION(Open RSP/IND) response: %d \n", event_cb->Error);

		switch (event_cb->Error) {
		case NET_ERR_NONE:
			WIFI_LOG(WIFI_INFO, "Activation succeeded\n");

			if (event_cb->Datalength == sizeof(net_profile_info_t))
				prof_info_p = (net_profile_info_t*)event_cb->Data;

			__libnet_state_changed_cb(event_cb->ProfileName, prof_info_p,
						WIFI_ERROR_NONE,
						WIFI_CONNECTION_STATE_CONNECTED,
						is_requested);
			return;
		case NET_ERR_TIME_OUT:
			WIFI_LOG(WIFI_ERROR, "Request time out!\n");
			break;
		case NET_ERR_OPERATION_ABORTED:
			WIFI_LOG(WIFI_ERROR, "Connction is aborted!\n");
			break;
		case NET_ERR_UNKNOWN_METHOD:
			WIFI_LOG(WIFI_ERROR, "Method not found!\n");
			break;
		case NET_ERR_UNKNOWN:
			WIFI_LOG(WIFI_ERROR, "Activation Failed!\n");
			break;
		default:
			WIFI_LOG(WIFI_ERROR, "Unknown Error!\n");
			break;
		}

		if (net_get_profile_info(event_cb->ProfileName, &prof_info) == NET_ERR_NONE)
			__libnet_state_changed_cb(event_cb->ProfileName, &prof_info,
						WIFI_ERROR_OPERATION_FAILED,
						WIFI_CONNECTION_STATE_DISCONNECTED,
						is_requested);
		else
			__libnet_state_changed_cb(event_cb->ProfileName, NULL,
						WIFI_ERROR_OPERATION_FAILED,
						WIFI_CONNECTION_STATE_DISCONNECTED,
						is_requested);

		break;
	case NET_EVENT_CLOSE_RSP:
		is_requested = true;
	case NET_EVENT_CLOSE_IND:
		if (strstr(event_cb->ProfileName, "/wifi_") == NULL) return;

		WIFI_LOG(WIFI_INFO, "Got Close RSP/IND\n");

		switch (event_cb->Error) {
		case NET_ERR_NONE:
			/* Successful PDP Deactivation */
			WIFI_LOG(WIFI_INFO, "Deactivation succeeded!\n");
			if (net_get_profile_info(event_cb->ProfileName, &prof_info) == NET_ERR_NONE)
				__libnet_state_changed_cb(event_cb->ProfileName, &prof_info,
							WIFI_ERROR_NONE,
							WIFI_CONNECTION_STATE_DISCONNECTED,
							is_requested);
			else
				__libnet_state_changed_cb(event_cb->ProfileName, NULL,
							WIFI_ERROR_NONE,
							WIFI_CONNECTION_STATE_DISCONNECTED,
							is_requested);
			return;
		case NET_ERR_TIME_OUT:
			WIFI_LOG(WIFI_ERROR, "Request time out!\n");
			break;
		case NET_ERR_IN_PROGRESS:
			WIFI_LOG(WIFI_ERROR, "Disconncting is in progress!\n");
			break;
		case NET_ERR_OPERATION_ABORTED:
			WIFI_LOG(WIFI_ERROR, "Disconnction is aborted!\n");
			break;
		case NET_ERR_UNKNOWN_METHOD:
			WIFI_LOG(WIFI_ERROR, "Service not found!\n");
			break;
		case NET_ERR_UNKNOWN:
			WIFI_LOG(WIFI_ERROR, "Deactivation Failed!\n");
			break;
		default:
			WIFI_LOG(WIFI_ERROR, "Unknown Error!\n");
			break;
		}

		if (net_get_profile_info(event_cb->ProfileName, &prof_info) == NET_ERR_NONE)
			__libnet_state_changed_cb(event_cb->ProfileName, &prof_info,
						WIFI_ERROR_OPERATION_FAILED,
						WIFI_CONNECTION_STATE_DISCONNECTED,
						is_requested);
		else
			__libnet_state_changed_cb(event_cb->ProfileName, NULL,
						WIFI_ERROR_OPERATION_FAILED,
						WIFI_CONNECTION_STATE_DISCONNECTED,
						is_requested);

		break;
	case NET_EVENT_NET_STATE_IND:
		if (strstr(event_cb->ProfileName, "/wifi_") == NULL) return;

		WIFI_LOG(WIFI_INFO, "Got State changed IND\n");
		net_state_type_t *profile_state = (net_state_type_t*)event_cb->Data;

		if (event_cb->Error == NET_ERR_NONE &&
		    event_cb->Datalength == sizeof(net_state_type_t)) {
			switch (*profile_state) {
			case NET_STATE_TYPE_ASSOCIATION:
				WIFI_LOG(WIFI_INFO,
					"Profile State : Association, profile name : %s\n",
					event_cb->ProfileName);
				break;
			case NET_STATE_TYPE_CONFIGURATION:
				WIFI_LOG(WIFI_INFO,
					"Profile State : Configuration, profile name : %s\n",
					event_cb->ProfileName);
				break;
			case NET_STATE_TYPE_IDLE:
			case NET_STATE_TYPE_FAILURE:
			case NET_STATE_TYPE_READY:
			case NET_STATE_TYPE_ONLINE:
			case NET_STATE_TYPE_DISCONNECT:
			case NET_STATE_TYPE_UNKNOWN:
			default:
				WIFI_LOG(WIFI_INFO,
					"Profile State : %d, profile name : %s\n", *profile_state,
					event_cb->ProfileName);
				return;
			}

			if (net_get_profile_info(event_cb->ProfileName, &prof_info) == NET_ERR_NONE)
				__libnet_state_changed_cb(event_cb->ProfileName, &prof_info,
							WIFI_ERROR_NONE,
							WIFI_CONNECTION_STATE_CONNECTING,
							is_requested);
			else
				__libnet_state_changed_cb(event_cb->ProfileName, NULL,
							WIFI_ERROR_NONE,
							WIFI_CONNECTION_STATE_CONNECTING,
							is_requested);
		}

		break;
	case NET_EVENT_WIFI_SCAN_RSP:
	case NET_EVENT_WIFI_SCAN_IND:
		WIFI_LOG(WIFI_ERROR, "Got wifi scan IND\n");
		__libnet_scan_cb(event_cb, is_requested);
		break;
	case NET_EVENT_WIFI_POWER_RSP:
		is_requested = true;
	case NET_EVENT_WIFI_POWER_IND:
		WIFI_LOG(WIFI_ERROR, "Got wifi power IND\n");
		__libnet_power_on_off_cb(event_cb, is_requested);
		break;
	default :
		WIFI_LOG(WIFI_ERROR, "Error! Unknown Event\n\n");
	}
}

bool _wifi_libnet_init(void)
{
	int rv;

	rv = net_register_client_ext((net_event_cb_t)__libnet_evt_cb, NET_DEVICE_WIFI, NULL);
	if (rv != NET_ERR_NONE)
		return false;

	return true;
}

bool _wifi_libnet_deinit(void)
{
	if (net_deregister_client_ext(NET_DEVICE_WIFI) != NET_ERR_NONE)
		return false;

	__libnet_clear_profile_list(&profile_iterator);
	g_slist_free_full(ap_handle_list, g_free);
	memset(&wifi_callbacks, 0, sizeof(struct _wifi_cb_s));

	return true;
}

int _wifi_activate(void)
{
	int rv;

	rv = net_wifi_power_on();
	if (rv == NET_ERR_NONE)
		return WIFI_ERROR_NONE;
	else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;

	return WIFI_ERROR_OPERATION_FAILED;
}

int _wifi_deactivate(void)
{
	int rv;

	rv = net_wifi_power_off();
	if (rv == NET_ERR_NONE)
		return WIFI_ERROR_NONE;
	else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;

	return WIFI_ERROR_OPERATION_FAILED;
}

bool _wifi_libnet_check_ap_validity(wifi_ap_h ap_h)
{
	GSList *list;
	int i = 0;

	for (list = ap_handle_list; list; list = list->next)
		if (ap_h == list->data) return true;

	for (;i < profile_iterator.count;i++)
		if (ap_h == &profile_iterator.profiles[i]) return true;

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
	const char *profile_header = "/net/connman/service/wifi_";
	int i = 0;
	int string_len = 0;

	if (profile_name == NULL || strlen(profile_name) <= strlen(profile_header)) {
		WIFI_LOG(WIFI_ERROR, "Error!!! Profile name is invalid\n");
		return false;
	}

	string_len = strlen(profile_name);

	if (strncmp(profile_header, profile_name, strlen(profile_header)) == 0) {
		for (;i < string_len;i++) {
			if (isgraph(profile_name[i]) == 0) {
				WIFI_LOG(WIFI_ERROR, "Error!!! Profile name is invalid\n");
				return false;
			}
		}
	} else {
		WIFI_LOG(WIFI_ERROR, "Error!!! Profile name is invalid\n");
		return false;
	}

	return NET_ERR_NONE;
}

bool _wifi_libnet_get_wifi_state(wifi_connection_state_e* connection_state)
{
	net_wifi_state_t wlan_state = 0;
	net_profile_name_t profile_name;

	if (net_get_wifi_state(&wlan_state, &profile_name) != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Error!! net_get_wifi_state() failed.\n");
		return false;
	}

	switch (wlan_state) {
	case WIFI_OFF:
	case WIFI_ON:
		*connection_state = WIFI_CONNECTION_STATE_DISCONNECTED;
		break;
	case WIFI_CONNECTING:
		*connection_state = WIFI_CONNECTION_STATE_CONNECTING;
		break;
	case WIFI_CONNECTED:
		*connection_state = WIFI_CONNECTION_STATE_CONNECTED;
		break;
	case WIFI_DISCONNECTING:
		*connection_state = WIFI_CONNECTION_STATE_DISCONNECTING;
		break;
	default :
		WIFI_LOG(WIFI_ERROR, "Error!! Unknown state\n");
		return false;
	}

	return true;
}

int _wifi_libnet_get_intf_name(char** name)
{
	if (profile_iterator.count == 0)
		__libnet_update_profile_iterator();

	if (profile_iterator.count == 0) {
		WIFI_LOG(WIFI_ERROR, "Error!! There is no AP\n");
		return WIFI_ERROR_OPERATION_FAILED;
	}

	*name = g_strdup(profile_iterator.profiles->ProfileInfo.Wlan.net_info.DevName);
	if (*name == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_scan_request(wifi_scan_finished_cb callback, void* user_data)
{
	int rv;
	rv = net_scan_wifi();

	if (rv == NET_ERR_NONE) {
		wifi_callbacks.scan_request_cb = callback;
		wifi_callbacks.scan_request_user_data = user_data;
		return WIFI_ERROR_NONE;
	} else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;

	return WIFI_ERROR_OPERATION_FAILED;
}

int _wifi_libnet_get_connected_profile(wifi_ap_h *ap)
{
	int i = 0;
	wifi_ap_h ap_h = NULL;

	__libnet_update_profile_iterator();

	for (;i < profile_iterator.count;i++) {
		if (profile_iterator.profiles[i].ProfileState == NET_STATE_TYPE_ONLINE ||
		    profile_iterator.profiles[i].ProfileState == NET_STATE_TYPE_READY) {
			ap_h = (wifi_ap_h)(&profile_iterator.profiles[i]);
			break;
		}
	}

	if (ap_h == NULL) {
		WIFI_LOG(WIFI_ERROR, "Error!! There is no connected AP.\n");
		return WIFI_ERROR_NO_CONNECTION;
	}

	*ap = g_try_malloc0(sizeof(net_profile_info_t));
	if (*ap == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	memcpy(*ap, ap_h, sizeof(net_profile_info_t));

	_wifi_libnet_add_to_ap_list(*ap);

	return WIFI_ERROR_NONE;
}

bool _wifi_libnet_foreach_found_aps(wifi_found_ap_cb callback, void *user_data)
{
	int i = 0;
	bool rv = true;

	__libnet_update_profile_iterator();

	if (profile_iterator.count == 0) {
		WIFI_LOG(WIFI_INFO, "There is no APs.\n");
		return true;
	}

	for (;i < profile_iterator.count;i++) {
		rv = callback((wifi_ap_h)(&profile_iterator.profiles[i]), user_data);
		if (rv == false) break;
	}

	return true;
}

int _wifi_libnet_open_profile(wifi_ap_h ap_h)
{
	net_profile_info_t *ap_info = ap_h;

	if (ap_info->ProfileInfo.Wlan.security_info.sec_mode == WLAN_SEC_MODE_IEEE8021X)
		return __libnet_connect_with_wifi_info(ap_info);
	else if (_wifi_libnet_check_profile_name_validity(ap_info->ProfileName) == false)
		return __libnet_connect_with_wifi_info(ap_info);
	else if (net_open_connection_with_profile(ap_info->ProfileName) != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_close_profile(wifi_ap_h ap_h)
{
	net_profile_info_t *ap_info = ap_h;

	if (net_close_connection(ap_info->ProfileName) != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_connect_with_wps(wifi_ap_h ap_h, wifi_wps_type_e type, const char *pin)
{
	net_profile_info_t *ap_info = ap_h;
	net_wifi_wps_info_t wps_info;
	memset(&wps_info, 0 , sizeof(net_wifi_wps_info_t));

	if (type == WIFI_WPS_TYPE_PIN) {
		wps_info.type = WIFI_WPS_PIN;
		g_strlcpy(wps_info.pin, pin, NET_WLAN_MAX_WPSPIN_LEN+1);
	} else
		wps_info.type = WIFI_WPS_PBC;

	if (net_wifi_enroll_wps(ap_info->ProfileName, &wps_info) != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

int _wifi_set_power_on_off_cb(wifi_device_state_changed_cb callback, void *user_data)
{
	if (wifi_callbacks.device_state_cb)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.device_state_cb = callback;
	wifi_callbacks.device_state_user_data = user_data;

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
	if (wifi_callbacks.bg_scan_cb)
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
	if (wifi_callbacks.connection_state_cb)
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
	if (net_modify_profile(ap_info->ProfileName, ap_info) != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}


