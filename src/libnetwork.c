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
	wifi_scan_finished_cb scan_hidden_ap_cb;
	void *scan_hidden_ap_user_data;
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

static struct _wifi_cb_s wifi_callbacks = {0,};
static struct _profile_list_s profile_iterator = {0, NULL};
static struct _profile_list_s hidden_profile_iterator = {0, NULL};


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
	}

	return "UNKNOWN";
}

static const char *__libnet_convert_ap_state_to_string(wifi_connection_state_e state)
{
	switch (state) {
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

static void __libnet_update_hidden_profile_iterator(GSList *ap_list)
{
	int count;
	GSList *list = ap_list;

	for (count = 0; list; list = list->next)
		count++;

	if (count == 0) {
		WIFI_LOG(WIFI_INFO, "No hidden AP found\n");
		return;
	}

	hidden_profile_iterator.count = count;
	hidden_profile_iterator.profiles = g_try_new0(net_profile_info_t, count);

	list = ap_list;
	for (count = 0; list; list = list->next) {
		net_wifi_connection_info_t *ap = list->data;
		net_profile_info_t *profile = &hidden_profile_iterator.profiles[count];

		g_strlcpy(profile->ProfileInfo.Wlan.essid, ap->essid, NET_WLAN_ESSID_LEN+1);
		profile->ProfileInfo.Wlan.security_info.sec_mode = ap->security_info.sec_mode;
		count++;
	}

	WIFI_LOG(WIFI_INFO, "Hidden AP count : %d\n", count);
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
							wifi_connection_state_e state)
{
	if (profile_name == NULL)
		return;

	if (profile_info == NULL) {
		WIFI_LOG(WIFI_ERROR, "Error!! Profile info not found! : %s\n", profile_name);
		return;
	}

	ap_handle_list = g_slist_append(ap_handle_list, (wifi_ap_h)profile_info);

	if (wifi_callbacks.connection_state_cb)
		wifi_callbacks.connection_state_cb(state, (wifi_ap_h)profile_info,
					wifi_callbacks.connection_state_user_data);

	ap_handle_list = g_slist_remove(ap_handle_list, (wifi_ap_h)profile_info);
}

static void __libnet_set_activated_cb(wifi_activated_cb user_cb, void *user_data)
{
	if (user_cb) {
		wifi_callbacks.activated_cb = user_cb;
		wifi_callbacks.activated_user_data = user_data;
	}
}

static void __libnet_activated_cb(wifi_error_e result)
{
	if (wifi_callbacks.activated_cb)
		wifi_callbacks.activated_cb(result, wifi_callbacks.activated_user_data);

	wifi_callbacks.activated_cb = NULL;
	wifi_callbacks.activated_user_data = NULL;
}

static void __libnet_set_deactivated_cb(wifi_disconnected_cb user_cb, void *user_data)
{
	if (user_cb) {
		wifi_callbacks.deactivated_cb = user_cb;
		wifi_callbacks.deactivated_user_data = user_data;
	}
}

static void __libnet_deactivated_cb(wifi_error_e result)
{
	if (wifi_callbacks.deactivated_cb)
		wifi_callbacks.deactivated_cb(result, wifi_callbacks.deactivated_user_data);

	wifi_callbacks.deactivated_cb = NULL;
	wifi_callbacks.deactivated_user_data = NULL;
}

static void __libnet_power_on_off_cb(net_event_info_t *event_cb, bool is_requested)
{
	if (wifi_callbacks.device_state_cb == NULL &&
	    wifi_callbacks.activated_cb == NULL &&
	    wifi_callbacks.deactivated_cb == NULL)
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
			__libnet_clear_profile_list(&profile_iterator);
			__libnet_clear_profile_list(&hidden_profile_iterator);
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

	__libnet_activated_cb(error_code);
	__libnet_deactivated_cb(error_code);

	if (wifi_callbacks.device_state_cb)
		wifi_callbacks.device_state_cb(state, wifi_callbacks.device_state_user_data);
}

static void __libnet_scan_cb(net_event_info_t *event_cb)
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

static void __libnet_hidden_scan_cb(net_event_info_t *event_cb)
{
	wifi_error_e error_code = WIFI_ERROR_NONE;

	__libnet_clear_profile_list(&hidden_profile_iterator);

	if (event_cb->Error != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Hidden scan failed!, Error [%d]\n", event_cb->Error);
		error_code = WIFI_ERROR_OPERATION_FAILED;
	} else if (event_cb->Data) {
		GSList *ap_list = event_cb->Data;
		__libnet_update_hidden_profile_iterator(ap_list);
	}

	if (wifi_callbacks.scan_hidden_ap_cb) {
		wifi_callbacks.scan_hidden_ap_cb(error_code, wifi_callbacks.scan_hidden_ap_user_data);
		wifi_callbacks.scan_hidden_ap_cb = NULL;
		wifi_callbacks.scan_hidden_ap_user_data = NULL;
	}
}

static void __libnet_set_connected_cb(wifi_connected_cb user_cb, void *user_data)
{
	if (user_cb) {
		wifi_callbacks.connected_cb = user_cb;
		wifi_callbacks.connected_user_data = user_data;
	}
}

static void __libnet_connected_cb(wifi_error_e result)
{
	if (wifi_callbacks.connected_cb)
		wifi_callbacks.connected_cb(result, wifi_callbacks.connected_user_data);

	wifi_callbacks.connected_cb = NULL;
	wifi_callbacks.connected_user_data = NULL;
}

static void __libnet_set_disconnected_cb(wifi_disconnected_cb user_cb, void *user_data)
{
	if (user_cb) {
		wifi_callbacks.disconnected_cb = user_cb;
		wifi_callbacks.disconnected_user_data = user_data;
	}
}

static void __libnet_disconnected_cb(wifi_error_e result)
{
	if (wifi_callbacks.disconnected_cb)
		wifi_callbacks.disconnected_cb(result, wifi_callbacks.disconnected_user_data);

	wifi_callbacks.disconnected_cb = NULL;
	wifi_callbacks.disconnected_user_data = NULL;
}

static void __libnet_evt_cb(net_event_info_t *event_cb, void *user_data)
{
	bool is_requested = false;
	net_profile_info_t *prof_info_p = NULL;
	net_profile_info_t prof_info;
	wifi_error_e result = WIFI_ERROR_NONE;

	switch (event_cb->Event) {
	case NET_EVENT_OPEN_RSP:
	case NET_EVENT_WIFI_WPS_RSP:
		is_requested = true;
		/* fall through */
	case NET_EVENT_OPEN_IND:
		if (_wifi_libnet_check_profile_name_validity(event_cb->ProfileName) != true)
			return;

		result = __libnet_convert_to_ap_error_type(event_cb->Error);
		WIFI_LOG(WIFI_INFO, "Got Open RSP/IND : %s\n",
			__libnet_convert_ap_error_type_to_string(result));

		if (is_requested)
			__libnet_connected_cb(result);

		switch (event_cb->Error) {
		case NET_ERR_NONE:
			WIFI_LOG(WIFI_INFO, "Connection open succeeded\n");

			if (event_cb->Datalength == sizeof(net_profile_info_t))
				prof_info_p = (net_profile_info_t*)event_cb->Data;

			__libnet_state_changed_cb(event_cb->ProfileName, prof_info_p,
							WIFI_CONNECTION_STATE_CONNECTED);
			return;
		case NET_ERR_ACTIVE_CONNECTION_EXISTS:
			WIFI_LOG(WIFI_INFO, "Connection already existed\n");
			return;
		default :
			WIFI_LOG(WIFI_ERROR, "Connection open failed!\n");
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
		WIFI_LOG(WIFI_INFO, "Got Close RSP/IND : %s\n",
			__libnet_convert_ap_error_type_to_string(result));

		if (is_requested)
			__libnet_disconnected_cb(result);

		switch (event_cb->Error) {
		case NET_ERR_NONE:
			WIFI_LOG(WIFI_INFO, "Connection close succeeded!\n");
			if (net_get_profile_info(event_cb->ProfileName, &prof_info) == NET_ERR_NONE)
				__libnet_state_changed_cb(event_cb->ProfileName, &prof_info,
							WIFI_CONNECTION_STATE_DISCONNECTED);
			else
				__libnet_state_changed_cb(event_cb->ProfileName, NULL,
							WIFI_CONNECTION_STATE_DISCONNECTED);
			return;
		default:
			WIFI_LOG(WIFI_ERROR, "Connection close failed!\n");
			break;
		}

		break;
	case NET_EVENT_NET_STATE_IND:
		if (_wifi_libnet_check_profile_name_validity(event_cb->ProfileName) != true)
			return;

		WIFI_LOG(WIFI_INFO, "Got State changed IND\n");

		if (event_cb->Datalength != sizeof(net_state_type_t))
			return;

		net_state_type_t *profile_state = (net_state_type_t*)event_cb->Data;
		wifi_connection_state_e ap_state = _wifi_convert_to_ap_state(*profile_state);

		WIFI_LOG(WIFI_INFO,
			"Profile State : %s, profile name : %s\n",
			__libnet_convert_ap_state_to_string(ap_state),
			event_cb->ProfileName);

		if (net_get_profile_info(event_cb->ProfileName, &prof_info) == NET_ERR_NONE)
			__libnet_state_changed_cb(event_cb->ProfileName, &prof_info, ap_state);
		else
			__libnet_state_changed_cb(event_cb->ProfileName, NULL, ap_state);


		break;
	case NET_EVENT_WIFI_SCAN_RSP:
	case NET_EVENT_WIFI_SCAN_IND:
		WIFI_LOG(WIFI_INFO, "Got Wi-Fi scan IND\n");
		__libnet_scan_cb(event_cb);
		break;
	case NET_EVENT_SPECIFIC_SCAN_RSP:
		WIFI_LOG(WIFI_INFO, "Got Wi-Fi hidden scan RSP\n");
		break;
	case NET_EVENT_SPECIFIC_SCAN_IND:
		WIFI_LOG(WIFI_INFO, "Got Wi-Fi hidden scan IND\n");
		__libnet_hidden_scan_cb(event_cb);
		break;
	case NET_EVENT_WIFI_POWER_RSP:
		is_requested = true;
		/* fall through */
	case NET_EVENT_WIFI_POWER_IND:
		WIFI_LOG(WIFI_INFO, "Got Wi-Fi power IND\n");
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
	__libnet_clear_profile_list(&hidden_profile_iterator);
	g_slist_free_full(ap_handle_list, g_free);
	ap_handle_list = NULL;
	memset(&wifi_callbacks, 0, sizeof(struct _wifi_cb_s));

	return true;
}

int _wifi_activate(wifi_activated_cb callback, void *user_data)
{
	int rv;

	rv = net_wifi_power_on();
	if (rv == NET_ERR_NONE) {
		__libnet_set_activated_cb(callback, user_data);
		return WIFI_ERROR_NONE;
	} else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;
	else if (rv == NET_ERR_ALREADY_EXISTS)
		return WIFI_ERROR_ALREADY_EXISTS;

	return WIFI_ERROR_OPERATION_FAILED;
}

int _wifi_deactivate(wifi_deactivated_cb callback, void *user_data)
{
	int rv;

	rv = net_wifi_power_off();
	if (rv == NET_ERR_NONE) {
		__libnet_set_deactivated_cb(callback, user_data);
		return WIFI_ERROR_NONE;
	} else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;
	else if (rv == NET_ERR_ALREADY_EXISTS)
		return WIFI_ERROR_ALREADY_EXISTS;

	return WIFI_ERROR_OPERATION_FAILED;
}

bool _wifi_libnet_check_ap_validity(wifi_ap_h ap_h)
{
	GSList *list;
	int i = 0;

	for (list = ap_handle_list; list; list = list->next)
		if (ap_h == list->data) return true;

	for (; i < profile_iterator.count; i++)
		if (ap_h == &profile_iterator.profiles[i]) return true;

	for (i = 0; i < hidden_profile_iterator.count; i++)
		if (ap_h == &hidden_profile_iterator.profiles[i]) return true;

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
		WIFI_LOG(WIFI_ERROR, "Error!!! Profile name is invalid\n");
		return false;
	}

	while (profile_name[i] != '\0') {
		if (isgraph(profile_name[i]) == 0) {
			WIFI_LOG(WIFI_ERROR, "Error!!! Profile name is invalid\n");
			return false;
		}
		i++;
	}

	return true;
}

bool _wifi_libnet_get_wifi_device_state(wifi_device_state_e *device_state)
{
	net_tech_info_t tech_info;

	if (net_get_technology_properties(NET_DEVICE_WIFI, &tech_info) != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Error!! net_get_technology_properties() failed.\n");
		return false;
	}

	if (tech_info.powered)
		*device_state = WIFI_DEVICE_STATE_ACTIVATED;
	else
		*device_state = WIFI_DEVICE_STATE_DEACTIVATED;

	WIFI_LOG(WIFI_ERROR, "Wi-Fi device state: %d", *device_state);

	return true;
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
		*connection_state = WIFI_CONNECTION_STATE_ASSOCIATION;
		break;
	case WIFI_CONNECTED:
		*connection_state = WIFI_CONNECTION_STATE_CONNECTED;
		break;
	case WIFI_DISCONNECTING:
		*connection_state = WIFI_CONNECTION_STATE_CONNECTED;
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

int _wifi_libnet_scan_request(wifi_scan_finished_cb callback, void *user_data)
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

int _wifi_libnet_scan_hidden_ap(const char *essid,
					wifi_scan_finished_cb callback, void *user_data)
{
	int rv;
	rv = net_specific_scan_wifi(essid);

	if (rv == NET_ERR_NONE) {
		wifi_callbacks.scan_hidden_ap_cb = callback;
		wifi_callbacks.scan_hidden_ap_user_data = user_data;
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

bool _wifi_libnet_foreach_found_hidden_aps(wifi_found_ap_cb callback, void *user_data)
{
	int i = 0;
	bool rv = true;

	if (hidden_profile_iterator.count == 0) {
		WIFI_LOG(WIFI_INFO, "There is no hidden APs.\n");
		return true;
	}

	for (;i < hidden_profile_iterator.count;i++) {
		rv = callback((wifi_ap_h)(&hidden_profile_iterator.profiles[i]), user_data);
		if (rv == false) break;
	}

	return true;
}

int _wifi_libnet_open_profile(wifi_ap_h ap_h, wifi_connected_cb callback, void *user_data)
{
	int rv;
	bool valid_profile;
	net_profile_name_t profile_name;
	net_profile_info_t *ap_info = ap_h;

	g_strlcpy(profile_name.ProfileName, ap_info->ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	valid_profile =
			_wifi_libnet_check_profile_name_validity(profile_name.ProfileName);

	if (valid_profile == true && ap_info->Favourite)
		rv = net_open_connection_with_profile(profile_name.ProfileName);
	else if (valid_profile == true &&
			ap_info->ProfileInfo.Wlan.security_info.sec_mode == WLAN_SEC_MODE_NONE)
		rv = net_open_connection_with_profile(profile_name.ProfileName);
	else
		rv = __libnet_connect_with_wifi_info(ap_info);

	if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	__libnet_set_connected_cb(callback, user_data);

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_close_profile(wifi_ap_h ap_h, wifi_disconnected_cb callback, void *user_data)
{
	net_profile_info_t *ap_info = ap_h;
	net_profile_name_t profile_name;

	g_strlcpy(profile_name.ProfileName, ap_info->ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	if (net_close_connection(profile_name.ProfileName) != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	__libnet_set_disconnected_cb(callback, user_data);

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_connect_with_wps(wifi_ap_h ap_h, wifi_connected_cb callback, void *user_data)
{
	net_profile_info_t *ap_info = ap_h;
	net_wifi_wps_info_t wps_info;
	net_profile_name_t profile_name;

	memset(&wps_info, 0 , sizeof(net_wifi_wps_info_t));
	g_strlcpy(profile_name.ProfileName, ap_info->ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	wps_info.type = WIFI_WPS_PBC;

	if (net_wifi_enroll_wps(profile_name.ProfileName, &wps_info) != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	__libnet_set_connected_cb(callback, user_data);

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_forget_ap(wifi_ap_h ap)
{
	int rv = 0;
	net_profile_name_t profile_name;
	net_profile_info_t *ap_info = ap;

	g_strlcpy(profile_name.ProfileName, ap_info->ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	rv = net_delete_profile(profile_name.ProfileName);
	if (rv != NET_ERR_NONE)
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
