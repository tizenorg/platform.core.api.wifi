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

#include <winet-wifi.h>

static GSList *ap_handle_list = NULL;

typedef struct {
	char *type;
	char *mode;
	char *ssid;
	char *security;
	char *passphrase;
	char *eap_type;
	char *eap_auth;
	char *identity;
	char *password;
	char *ca_cert_file;
	char *client_cert_file;
	char *private_key_file;
	char *private_key_password;
} net_wifi_connect_service_info_t;

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
	char *profiles;
};

static struct _wifi_cb_s wifi_callbacks = {0,};
static struct _profile_list_s profile_iterator = {0, NULL};
static struct _profile_list_s hidden_profile_iterator = {0, NULL};

/*For connection which CAPI send some message to WiNet daemon*/
static net_wifi_connection_info_t net_wifi_conn_info;

/*For connection which CAPI send some message to WiNet daemon*/
void _set_wifi_conn_info(net_wifi_connection_info_t *wifi_conn_info)
{
	g_strlcpy(net_wifi_conn_info.essid, wifi_conn_info->essid,
					NET_WLAN_ESSID_LEN+1);
	net_wifi_conn_info.wlan_mode = wifi_conn_info->wlan_mode;
	memcpy(&net_wifi_conn_info.security_info,
					&wifi_conn_info->security_info,
					sizeof(wlan_security_info_t));
}

/*For connection which CAPI send some message to WiNet daemon*/
net_wifi_connection_info_t *_get_wifi_conn_info(void)
{
	return &net_wifi_conn_info;
}

net_state_type_t _get_service_state_type(const char *state)
{
	if (!g_strcmp0(state, "idle"))
		return NET_STATE_TYPE_IDLE;
	else if (!g_strcmp0(state, "association"))
		return NET_STATE_TYPE_ASSOCIATION;
	else if (!g_strcmp0(state, "configuration"))
		return NET_STATE_TYPE_CONFIGURATION;
	else if (!g_strcmp0(state, "ready"))
		return NET_STATE_TYPE_READY;
	else if (!g_strcmp0(state, "online"))
		return NET_STATE_TYPE_ONLINE;
	else if (!g_strcmp0(state, "disconnect"))
		return NET_STATE_TYPE_DISCONNECT;
	else if (!g_strcmp0(state, "failure"))
		return NET_STATE_TYPE_FAILURE;
	else
		return NET_STATE_TYPE_UNKNOWN;
}

const char *_get_ip_config_str(net_ip_config_type_t ip_config_type)
{
	switch (ip_config_type) {
	case NET_IP_CONFIG_TYPE_STATIC:
		return "manual";
	case NET_IP_CONFIG_TYPE_DYNAMIC:
		return "dhcp";
	case NET_IP_CONFIG_TYPE_AUTO_IP:
		return "dhcp";
	case NET_IP_CONFIG_TYPE_FIXED:
		return "fixed";
	case NET_IP_CONFIG_TYPE_OFF:
		return "off";
	}

	return NULL;
}

/*static wifi_error_e __libnet_convert_to_ap_error_type(net_err_t err_type)
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
}*/

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

	// DELETE: net_get_profile_list(NET_DEVICE_WIFI, &wifi_profiles.profiles, &wifi_profiles.count);
	WIFI_LOG(WIFI_INFO, "Wifi profile count : %d\n", wifi_profiles.count);

	if (wifi_profiles.count == 0)
		return;

	profile_iterator.count = wifi_profiles.count;
	profile_iterator.profiles = wifi_profiles.profiles;
}

/*static void __libnet_update_hidden_profile_iterator(GSList *ap_list)
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
}*/

/*static void __libnet_convert_profile_info_to_wifi_info(net_wifi_connection_info_t *wifi_info,
								net_profile_info_t *ap_info)
{
	g_strlcpy(wifi_info->essid, ap_info->ProfileInfo.Wlan.essid, NET_WLAN_ESSID_LEN+1);
	wifi_info->wlan_mode = ap_info->ProfileInfo.Wlan.wlan_mode;
	memcpy(&wifi_info->security_info, &ap_info->ProfileInfo.Wlan.security_info, sizeof(wlan_security_info_t));
}*/

/**
 * Added
 */
static char *__convert_eap_type_to_string(gchar eap_type)
{
	switch (eap_type) {
	case WLAN_SEC_EAP_TYPE_PEAP:
		return "peap";

	case WLAN_SEC_EAP_TYPE_TLS:
		return "tls";

	case WLAN_SEC_EAP_TYPE_TTLS:
		return "ttls";

	case WLAN_SEC_EAP_TYPE_SIM:
		return "sim";

	case WLAN_SEC_EAP_TYPE_AKA:
		return "aka";

	default:
		return NULL;
	}
}

static char *__convert_eap_auth_to_string(gchar eap_auth)
{
	switch (eap_auth) {
	case WLAN_SEC_EAP_AUTH_NONE:
		return "NONE";

	case WLAN_SEC_EAP_AUTH_PAP:
		return "PAP";

	case WLAN_SEC_EAP_AUTH_MSCHAP:
		return "MSCHAP";

	case WLAN_SEC_EAP_AUTH_MSCHAPV2:
		return "MSCHAPV2";

	case WLAN_SEC_EAP_AUTH_GTC:
		return "GTC";

	case WLAN_SEC_EAP_AUTH_MD5:
		return "MD5";

	default:
		return NULL;
	}
}

char* _net_print_error(net_err_t error)
{
	switch (error) {
		/** No error */
	case NET_ERR_NONE:
		return "NET_ERR_NONE";

		/* Common Error value */

		/** Error unknown */
	case NET_ERR_UNKNOWN:
		return "NET_ERR_UNKNOWN";

		/* Client Register related Errors used in API return */

		/** Application is already registered */
	case NET_ERR_APP_ALREADY_REGISTERED:
		return "NET_ERR_APP_ALREADY_REGISTERED";
		/** Application is not registered */
	case NET_ERR_APP_NOT_REGISTERED:
		return "NET_ERR_APP_NOT_REGISTERED";

		/* Connection Related Error */

		/** No active connection exists for the given profile name */
	case NET_ERR_NO_ACTIVE_CONNECTIONS:
		return "NET_ERR_NO_ACTIVE_CONNECTIONS";
		/** Active connection already exists for the given profile name  */
	case NET_ERR_ACTIVE_CONNECTION_EXISTS:
		return "NET_ERR_ACTIVE_CONNECTION_EXISTS";

		/** Connection failure : out of range */
	case NET_ERR_CONNECTION_OUT_OF_RANGE:
		return "NET_ERR_CONNECTION_OUT_OF_RANGE";
		/** Connection failure : pin missing */
	case NET_ERR_CONNECTION_PIN_MISSING:
		return "NET_ERR_CONNECTION_PIN_MISSING";
		/** Connection failure : dhcp failed */
	case NET_ERR_CONNECTION_DHCP_FAILED:
		return "NET_ERR_CONNECTION_DHCP_FAILED";
		/** Connection failure */
	case NET_ERR_CONNECTION_CONNECT_FAILED:
		return "NET_ERR_CONNECTION_CONNECT_FAILED";
		/** Connection failure : login failed */
	case NET_ERR_CONNECTION_LOGIN_FAILED:
		return "NET_ERR_CONNECTION_LOGIN_FAILED";
		/** Connection failure : authentication failed */
	case NET_ERR_CONNECTION_AUTH_FAILED:
		return "NET_ERR_CONNECTION_AUTH_FAILED";
		/** Connection failure : invalid key */
	case NET_ERR_CONNECTION_INVALID_KEY:
		return "NET_ERR_CONNECTION_INVALID_KEY";

		/* Other Error */

		/** Access is denied */
	case NET_ERR_ACCESS_DENIED:
		return "NET_ERR_ACCESS_DENIED";
		/** Operation is in progress */
	case NET_ERR_IN_PROGRESS:
		return "NET_ERR_IN_PROGRESS";
		/** Operation was aborted by client or network*/
	case NET_ERR_OPERATION_ABORTED:
		return "NET_ERR_OPERATION_ABORTED";
		/** Invalid value of API parameter */
	case NET_ERR_INVALID_PARAM:
		return "NET_ERR_INVALID_PARAM";
		/** invalid operation depending on current state */
	case NET_ERR_INVALID_OPERATION:
		return "NET_ERR_INVALID_OPERATION";

		/** Feature not supported */
	case NET_ERR_NOT_SUPPORTED:
		return "NET_ERR_NOT_SUPPORTED";
		/** TimeOut Error */
	case NET_ERR_TIME_OUT:
		return "NET_ERR_TIME_OUT";
		/** Network service is not available*/
	case NET_ERR_NO_SERVICE:
		return "NET_ERR_NO_SERVICE";
		/** DBus can't find appropriate method */
	case NET_ERR_UNKNOWN_METHOD:
		return "NET_ERR_UNKNOWN_METHOD";
		/** Operation is restricted */
	case NET_ERR_SECURITY_RESTRICTED:
		return "NET_ERR_SECURITY_RESTRICTED";
		/** WiFi driver on/off failed */
	case NET_ERR_WIFI_DRIVER_FAILURE:
		return "NET_ERR_WIFI_DRIVER_FAILURE";
	default:
		return "INVALID";
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

wifi_error_e connman_lib2capi_result(enum connman_lib_err_e result)
{
	/*
	 * TODO:
	 */
	wifi_error_e tmp = WIFI_ERROR_NONE;
	return tmp;
}

static void connman_service_connect_cb(
					enum connman_lib_err_e result,
					void *user_data)
{
	WIFI_LOG(WIFI_INFO, "callback: %d\n", result);

	__libnet_connected_cb(connman_lib2capi_result(result));
}

static void connman_service_disconnect_cb(
					enum connman_lib_err_e result,
					void *user_data)
{
	WIFI_LOG(WIFI_INFO, "callback: %d\n", result);

	__libnet_disconnected_cb(connman_lib2capi_result(result));
}

static int __net_dbus_set_agent_passphrase(const char *path,
						 const char *passphrase)
{
	int ret_val;
	char *service_id;

	if (NULL == passphrase || strlen(passphrase) <= 0) {
		WIFI_LOG(WIFI_ERROR, "Invalid param \n");
		return NET_ERR_INVALID_PARAM;
	}

	service_id = g_strrstr(path, "/") + 1;
	ret_val = winet_wifi_update_agent_passphrase(service_id, passphrase);
	if (NET_ERR_NONE != ret_val) {
		WIFI_LOG(WIFI_ERROR,
			"__net_dbus_set_agent_field failed. Error = %d \n",
			ret_val);
		return ret_val;
	}

	WIFI_LOG(WIFI_ERROR, "Successfully sent passphrase\n");

	return NET_ERR_NONE;
}

static int __net_dbus_connect_service(wifi_ap_h ap_h,
		const net_wifi_connect_service_info_t *wifi_connection_info)
{
	net_err_t Error = NET_ERR_NONE;

	struct connman_service *service = ap_h;
	if (!service)
		return NET_ERR_INVALID_PARAM;

	if (g_strcmp0(wifi_connection_info->security, "ieee8021x") == 0) {
		/* Create the EAP config file
		 * TODO:
		 */
		/*Error = _net_dbus_set_eap_config_fields(wifi_connection_info);*/
		if (NET_ERR_NONE != Error) {
			WIFI_LOG(WIFI_ERROR, "Fail to create eap_config\n");

			goto done;
		}
	} else if (g_strcmp0(wifi_connection_info->security, "none") != 0) {
		Error = __net_dbus_set_agent_passphrase(
				connman_service_get_path(service),
				wifi_connection_info->passphrase);
		if (NET_ERR_NONE != Error) {
			WIFI_LOG(WIFI_ERROR, "Fail to set agent_passphrase\n");

			goto done;
		}
	}

	connman_service_connect(service, connman_service_connect_cb, NULL);

done:
	return Error;
}

/** This function is used only to open Wi-Fi connection with hidden APs */
static int __net_open_connection_with_wifi_info(wifi_ap_h ap_h, const net_wifi_connection_info_t* wifi_info)
{
	net_err_t Error = NET_ERR_NONE;

	net_wifi_connect_service_info_t wifi_connection_info;
	memset(&wifi_connection_info, 0, sizeof(net_wifi_connect_service_info_t));

	wifi_connection_info.type = g_strdup("wifi");

	if (wifi_info->wlan_mode == NETPM_WLAN_CONNMODE_ADHOC)
		wifi_connection_info.mode = g_strdup("adhoc");
	else
		wifi_connection_info.mode = g_strdup("managed");

	wifi_connection_info.ssid = g_strdup(wifi_info->essid);

	switch (wifi_info->security_info.sec_mode) {
	case WLAN_SEC_MODE_NONE:
		wifi_connection_info.security = g_strdup("none");
		break;

	case WLAN_SEC_MODE_WEP:
		wifi_connection_info.security = g_strdup("wep");
		wifi_connection_info.passphrase =
				g_strdup(wifi_info->security_info.authentication.wep.wepKey);
		break;

	/** WPA-PSK(equivalent to WPA-NONE in case of Ad-Hoc) */
	case WLAN_SEC_MODE_WPA_PSK:
		wifi_connection_info.security = g_strdup("psk");
		wifi_connection_info.passphrase =
				g_strdup(wifi_info->security_info.authentication.psk.pskKey);
		break;

	/** WPA2-PSK */
	/** WPA-PSK / WPA2-PSK supported */
	case WLAN_SEC_MODE_WPA2_PSK:
		wifi_connection_info.security = g_strdup("rsn");
		wifi_connection_info.passphrase =
				g_strdup(wifi_info->security_info.authentication.psk.pskKey);
		break;

	case WLAN_SEC_MODE_IEEE8021X:
		wifi_connection_info.security = g_strdup("ieee8021x");

		wifi_connection_info.eap_type = g_strdup(
				__convert_eap_type_to_string(
						wifi_info->security_info.authentication.eap.eap_type));
		wifi_connection_info.eap_auth = g_strdup(
				__convert_eap_auth_to_string(
						wifi_info->security_info.authentication.eap.eap_auth));

		if (wifi_info->security_info.authentication.eap.username[0] != '\0')
			wifi_connection_info.identity =
					g_strdup(wifi_info->security_info.authentication.eap.username);

		if (wifi_info->security_info.authentication.eap.password[0] != '\0')
			wifi_connection_info.password =
					g_strdup(wifi_info->security_info.authentication.eap.password);

		if (wifi_info->security_info.authentication.eap.ca_cert_filename[0] != '\0')
			wifi_connection_info.ca_cert_file =
					g_strdup(wifi_info->security_info.authentication.eap.ca_cert_filename);

		if (wifi_info->security_info.authentication.eap.client_cert_filename[0] != '\0')
			wifi_connection_info.client_cert_file =
					g_strdup(wifi_info->security_info.authentication.eap.client_cert_filename);

		if (wifi_info->security_info.authentication.eap.private_key_filename[0] != '\0')
			wifi_connection_info.private_key_file =
					g_strdup(wifi_info->security_info.authentication.eap.private_key_filename);

		if (wifi_info->security_info.authentication.eap.private_key_passwd[0] != '\0')
			wifi_connection_info.private_key_password =
					g_strdup(wifi_info->security_info.authentication.eap.private_key_passwd);

		break;
	default:
		WIFI_LOG(WIFI_ERROR, "Invalid security type\n");

		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_dbus_connect_service(ap_h, &wifi_connection_info);
	if (Error != NET_ERR_NONE)
		WIFI_LOG(WIFI_ERROR, "Failed to request connect service. Error [%s]\n",
				_net_print_error(Error));
	else
		WIFI_LOG(WIFI_ERROR, "Successfully requested to connect service\n");

	g_free(wifi_connection_info.type);
	g_free(wifi_connection_info.mode);
	g_free(wifi_connection_info.ssid);
	g_free(wifi_connection_info.security);
	g_free(wifi_connection_info.passphrase);
	g_free(wifi_connection_info.eap_type);
	g_free(wifi_connection_info.eap_auth);
	g_free(wifi_connection_info.identity);
	g_free(wifi_connection_info.password);
	g_free(wifi_connection_info.ca_cert_file);
	g_free(wifi_connection_info.client_cert_file);
	g_free(wifi_connection_info.private_key_file);
	g_free(wifi_connection_info.private_key_password);

	return Error;
}

static int __libnet_connect_with_wifi_info(wifi_ap_h ap_h, wifi_connected_cb callback, void *user_data)
{
	net_wifi_connection_info_t *wifi_info;

	wifi_info = _get_wifi_conn_info();

	if (__net_open_connection_with_wifi_info(ap_h, wifi_info) != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

/*static void __libnet_state_changed_cb(char *profile_name, net_profile_info_t *profile_info,
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
}*/

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

static void __libnet_set_scan_request_cb(wifi_disconnected_cb user_cb, void *user_data)
{
	if (user_cb) {
		wifi_callbacks.scan_request_cb = user_cb;
		wifi_callbacks.scan_request_user_data = user_data;
	}
}

/*static void __libnet_scan_request_cb(wifi_error_e result)
{
	if (wifi_callbacks.scan_request_cb)
		wifi_callbacks.scan_request_cb(result, wifi_callbacks.scan_request_user_data);

	wifi_callbacks.scan_request_cb = NULL;
	wifi_callbacks.scan_request_user_data = NULL;
}*/

/*static void __libnet_power_on_off_cb(net_event_info_t *event_cb, bool is_requested)
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
}*/

/*static void __libnet_evt_cb(net_event_info_t *event_cb, void *user_data)
{
	bool is_requested = false;
	net_profile_info_t *prof_info_p = NULL;
	net_profile_info_t prof_info;
	wifi_error_e result = WIFI_ERROR_NONE;

	switch (event_cb->Event) {
	case NET_EVENT_OPEN_RSP:
	case NET_EVENT_WIFI_WPS_RSP:
		is_requested = true;
		 fall through
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

		//DELETE:

		if (net_get_profile_info(event_cb->ProfileName, &prof_info) == NET_ERR_NONE)
			__libnet_state_changed_cb(event_cb->ProfileName, &prof_info,
						WIFI_CONNECTION_STATE_DISCONNECTED);
		else
			__libnet_state_changed_cb(event_cb->ProfileName, NULL,
						WIFI_CONNECTION_STATE_DISCONNECTED);

		break;
	case NET_EVENT_CLOSE_RSP:
		is_requested = true;
		 fall through
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
			//DELETE:
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

		//DELETE:
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
		 fall through
	case NET_EVENT_WIFI_POWER_IND:
		WIFI_LOG(WIFI_INFO, "Got Wi-Fi power IND\n");
		__libnet_power_on_off_cb(event_cb, is_requested);
		break;
	default :
		WIFI_LOG(WIFI_ERROR, "Error! Unknown Event\n\n");
	}
}*/

bool _wifi_libnet_init(void)
{
	int rv = NET_ERR_NONE;
	/*rv = net_register_client_ext((net_event_cb_t)__libnet_evt_cb, NET_DEVICE_WIFI, NULL);*/
/*	net_register_client_ext((net_event_cb_t)__libnet_evt_cb, NET_DEVICE_WIFI, NULL);
	rv = initialize_wifi_ls2_calls();*/
	connman_lib_init();
	if (rv != NET_ERR_NONE)
		return false;

	return true;
}

bool _wifi_libnet_deinit(void)
{
	//DELETE:
/*	if (net_deregister_client_ext(NET_DEVICE_WIFI) != NET_ERR_NONE)
		return false;*/

	__libnet_clear_profile_list(&profile_iterator);
	__libnet_clear_profile_list(&hidden_profile_iterator);
	g_slist_free_full(ap_handle_list, g_free);
	ap_handle_list = NULL;
	memset(&wifi_callbacks, 0, sizeof(struct _wifi_cb_s));
	connman_lib_deinit();
	return true;
}

static void __connman_technology_powered_on_cb(
					enum connman_lib_err_e result,
					void *user_data)
{
	WIFI_LOG(WIFI_INFO, "callback: %d\n", result);

	__libnet_activated_cb(connman_lib2capi_result(result));
}

static void __connman_technology_powered_off_cb(
					enum connman_lib_err_e result,
					void *user_data)
{
	WIFI_LOG(WIFI_INFO, "callback: %d\n", result);

	__libnet_deactivated_cb(connman_lib2capi_result(result));
}

int _wifi_activate(wifi_activated_cb callback, void *user_data)
{
	/*int rv;

	rv = net_wifi_power_on();
	if (rv == NET_ERR_NONE) {
		__libnet_set_activated_cb(callback, user_data);
		return WIFI_ERROR_NONE;
	} else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;
	else if (rv == NET_ERR_ALREADY_EXISTS)
		return WIFI_ERROR_ALREADY_EXISTS;

	return WIFI_ERROR_OPERATION_FAILED;*/

	/*
	 * New capi
	 */
	struct connman_technology *technology =
					connman_get_technology(TECH_TYPE_WIFI);
	if (!technology)
		return WIFI_ERROR_OPERATION_FAILED;

	__libnet_set_activated_cb(callback, user_data);

	connman_enable_technology(technology,
					__connman_technology_powered_on_cb,
					NULL);

	return WIFI_ERROR_NONE;
}

int _wifi_deactivate(wifi_deactivated_cb callback, void *user_data)
{
	/*int rv;

	rv = net_wifi_power_off();
	if (rv == NET_ERR_NONE) {
		__libnet_set_deactivated_cb(callback, user_data);
		return WIFI_ERROR_NONE;
	} else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;
	else if (rv == NET_ERR_ALREADY_EXISTS)
		return WIFI_ERROR_ALREADY_EXISTS;

	return WIFI_ERROR_OPERATION_FAILED;*/

	/*
	 * New capi
	 */
	struct connman_technology *technology =
					connman_get_technology(TECH_TYPE_WIFI);
	if (!technology)
		return WIFI_ERROR_OPERATION_FAILED;

	__libnet_set_deactivated_cb(callback, user_data);

	connman_disable_technology(technology,
					__connman_technology_powered_off_cb,
					NULL);

	return WIFI_ERROR_NONE;
}

bool _wifi_libnet_check_ap_validity(wifi_ap_h ap_h)
{
	struct connman_service *service = ap_h;
	if (!service)
		return NET_ERR_INVALID_PARAM;

	const char *name = connman_service_get_name(service);

	if (!name)
		return false;

	return true;
}

void _wifi_libnet_add_to_ap_list(wifi_ap_h ap_h)
{
	ap_handle_list = g_slist_append(ap_handle_list, ap_h);
}

void _wifi_libnet_remove_from_ap_list(wifi_ap_h ap_h)
{
	net_profile_info_t *ap_info = ap_h;
	ap_handle_list = g_slist_remove(ap_handle_list, ap_info);
	g_free(ap_info->essid);
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
	struct connman_technology *technology;
	bool powered = false;

	technology = connman_get_technology(TECH_TYPE_WIFI);

	if (technology)
		powered = connman_get_technology_powered(technology);

	if (powered)
		*device_state = WIFI_DEVICE_STATE_ACTIVATED;
	else
		*device_state = WIFI_DEVICE_STATE_DEACTIVATED;

	WIFI_LOG(WIFI_ERROR, "Wi-Fi device state: %d", *device_state);

	return true;
}

bool _wifi_libnet_get_wifi_state(wifi_connection_state_e* connection_state)
{
	net_wifi_state_t wlan_state = 0;


	// DELETE:
	/*net_profile_name_t profile_name;
	if (net_get_wifi_state(&wlan_state, &profile_name) != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Error!! net_get_wifi_state() failed.\n");
		return false;
	}*/

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

	/**name = g_strdup(profile_iterator.profiles->ProfileInfo.Wlan.net_info.DevName);*/
	if (*name == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_scan_request(wifi_scan_finished_cb callback, void *user_data)
{
	int rv = NET_ERR_NONE;
	struct connman_technology *technology =
				connman_get_technology(TECH_TYPE_WIFI);

	__libnet_set_scan_request_cb(callback, user_data);

	rv = connman_scan_technology(technology);

	if (rv == NET_ERR_NONE) {
		return WIFI_ERROR_NONE;
	} else if (rv == NET_ERR_INVALID_OPERATION)
		return WIFI_ERROR_INVALID_OPERATION;

	return WIFI_ERROR_OPERATION_FAILED;
}

int _wifi_libnet_scan_hidden_ap(const char *essid,
					wifi_scan_finished_cb callback, void *user_data)
{
	int rv = NET_ERR_NONE;
	// DELETE:
	/*rv = net_specific_scan_wifi(essid)*/;

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
	wifi_ap_h ap_h = NULL;
	GList *iter;
	GList *connman_services_list = NULL;
	const char *state;
	net_state_type_t state_type;
	/*
	 * update service TODO
	 */

	/*
	 * Filter the service
	 */
	connman_services_list = connman_get_services();

	for (iter = connman_services_list; iter != NULL; iter = iter->next) {
		struct connman_service *service =
		    (struct connman_service *)(iter->data);

		state = connman_service_get_state(service);
		state_type = _get_service_state_type(state);
		if (( state_type == NET_STATE_TYPE_ONLINE) ||
					(state_type == NET_STATE_TYPE_READY))
			ap_h = (wifi_ap_h)service;
	}

	if (!ap_h) {
		WIFI_LOG(WIFI_ERROR, "Error!! There is no connected AP.\n");
		return WIFI_ERROR_NO_CONNECTION;
	}

	*ap = g_try_malloc0(sizeof(net_profile_info_t));
	if (*ap == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	((net_profile_info_t *) (*ap))->essid =
				g_strdup(connman_service_get_path(ap_h));

	_wifi_libnet_add_to_ap_list(*ap);

	return WIFI_ERROR_NONE;
}

bool _wifi_libnet_foreach_found_aps(wifi_found_ap_cb callback, void *user_data)
{
	bool rv = true;
	GList *iter;
	GList *connman_services_list = NULL;

	/*
	 * update all services TODO
	 */

	connman_services_list = connman_get_services();

	if (g_list_length(connman_services_list) == 0) {
		WIFI_LOG(WIFI_INFO, "There is no APs.\n");
		return true;
	}

	for (iter = connman_services_list; iter != NULL; iter = iter->next) {
		rv = callback((wifi_ap_h)(iter->data), user_data);
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
	 /*int rv = NET_ERR_NONE;

	 	bool valid_profile;
	 * 	net_profile_info_t *ap_info = ap_h;
	 * g_strlcpy(profile_name.ProfileName, ap_info->ProfileName, NET_PROFILE_NAME_LEN_MAX+1);*/

	/*valid_profile =
			_wifi_libnet_check_profile_name_validity(profile_name.ProfileName);*/

	// DELETE:
/*	if (valid_profile == true && ap_info->Favourite)
		rv = net_open_connection_with_profile(profile_name.ProfileName);
	else if (valid_profile == true &&
			ap_info->ProfileInfo.Wlan.security_info.sec_mode == WLAN_SEC_MODE_NONE)
		rv = net_open_connection_with_profile(profile_name.ProfileName);
	else
		rv = __libnet_connect_with_wifi_info(ap_info);*/

/*	if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	__libnet_set_connected_cb(callback, user_data);

	return WIFI_ERROR_NONE;*/

	int rv = NET_ERR_NONE;
	struct connman_service* service = ap_h;

	__libnet_set_connected_cb(callback, user_data);

	if (connman_service_get_favorite(service))
		connman_service_connect(service, connman_service_connect_cb, NULL);
	else
		rv = __libnet_connect_with_wifi_info(ap_h, callback, user_data);

	if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;

}

int _wifi_libnet_close_profile(wifi_ap_h ap_h, wifi_disconnected_cb callback, void *user_data)
{
/*	net_profile_info_t *ap_info = ap_h;
	net_profile_name_t profile_name;

	g_strlcpy(profile_name.ProfileName, ap_info->ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	//DELETE:
	if (net_close_connection(profile_name.ProfileName) != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	__libnet_set_disconnected_cb(callback, user_data);*/

	struct connman_service *service = ap_h;
	if (!service)
		return NET_ERR_INVALID_PARAM;

	__libnet_set_disconnected_cb(callback, user_data);
	connman_service_disconnect(service, connman_service_disconnect_cb, NULL);

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_connect_with_wps(wifi_ap_h ap_h, wifi_connected_cb callback, void *user_data)
{
/*	net_profile_info_t *ap_info = ap_h;
	net_wifi_wps_info_t wps_info;
	net_profile_name_t profile_name;

	memset(&wps_info, 0 , sizeof(net_wifi_wps_info_t));
	g_strlcpy(profile_name.ProfileName, ap_info->ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	wps_info.type = WIFI_WPS_PBC;

	// DELETE:

	if (net_wifi_enroll_wps(profile_name.ProfileName, &wps_info) != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	__libnet_set_connected_cb(callback, user_data);*/

	int rv = NET_ERR_NONE;
	struct connman_service *service = ap_h;
	if (!service)
		return NET_ERR_INVALID_PARAM;

	__libnet_set_connected_cb(callback, user_data);

	if (connman_service_get_favorite(service))
		connman_service_connect(service, connman_service_connect_cb, NULL);
	else
		rv = __libnet_connect_with_wifi_info(ap_h, callback, user_data);

	if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_forget_ap(wifi_ap_h ap)
{
/*	int rv = 0;
	net_profile_name_t profile_name;
	net_profile_info_t *ap_info = ap;

	g_strlcpy(profile_name.ProfileName, ap_info->ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	// DELETE:
	rv = net_delete_profile(profile_name.ProfileName);
	if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;*/

	int rv = NET_ERR_NONE;
	struct connman_service *service = ap;
	if (!service)
		return NET_ERR_INVALID_PARAM;

	connman_service_remove(service);

	if (rv != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

void connman_technology_set_device_state_changed_cb(
				struct connman_technology *technology,
				void *user_data)
{
	struct common_reply_data *reply_data;
	bool powered;

	reply_data = user_data;
	if (!reply_data)
		return;

	if (!technology)
		return;

	powered = connman_get_technology_powered(technology);

	if (reply_data->cb) {
		wifi_device_state_e state;
		state = powered ? WIFI_DEVICE_STATE_ACTIVATED :
						WIFI_DEVICE_STATE_DEACTIVATED;
		wifi_device_state_changed_cb cb = reply_data->cb;
		cb(state, reply_data->data);
	}
}

int _wifi_set_power_on_off_cb(wifi_device_state_changed_cb callback, void *user_data)
{
/*	if (wifi_callbacks.device_state_cb)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.device_state_cb = callback;
	wifi_callbacks.device_state_user_data = user_data;

	return WIFI_ERROR_NONE;*/

	/*
	 * New capi
	 */
/*	struct common_reply_data *reply_data;

	reply_data =
	    common_reply_data_new(callback, user_data, NULL, TRUE);*/

	connman_technology_set_property_changed_cb(
			connman_get_technology(TECH_TYPE_WIFI),
			TECH_PROP_POWERED,
			connman_technology_set_device_state_changed_cb,
			user_data);

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

/*int _wifi_update_ap_info(net_profile_info_t *ap_info)
{
	// DELETE:
	if (net_modify_profile(ap_info->ProfileName, ap_info) != NET_ERR_NONE)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}*/
