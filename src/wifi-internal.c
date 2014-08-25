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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>

#include <winet-wifi.h>

#include <connman-lib.h>
#include <connman-manager.h>
#include <connman-technology.h>
#include <connman-service.h>

#include "wifi-internal.h"

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

static struct _wifi_cb_s wifi_callbacks = {0,};

/*For connection which CAPI send some message to WiNet daemon*/
static net_wifi_connection_info_t net_wifi_conn_info;

/*For connection which CAPI send some message to WiNet daemon*/
void _wifi_set_conn_info(net_wifi_connection_info_t *wifi_conn_info)
{
	g_strlcpy(net_wifi_conn_info.essid, wifi_conn_info->essid,
					NET_WLAN_ESSID_LEN+1);
	net_wifi_conn_info.wlan_mode = wifi_conn_info->wlan_mode;
	memcpy(&net_wifi_conn_info.security_info,
					&wifi_conn_info->security_info,
					sizeof(wlan_security_info_t));
}

/*For connection which CAPI send some message to WiNet daemon*/
net_wifi_connection_info_t *_wifi_get_conn_info(void)
{
	return &net_wifi_conn_info;
}

net_state_type_t _wifi_get_service_state_type(const char *state)
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

net_ip_config_type_t _wifi_get_ip_config_type(const char *config)
{
	net_ip_config_type_t config_type;

	if (!g_strcmp0(config, "manual"))
		config_type = NET_IP_CONFIG_TYPE_STATIC;
	else if (!g_strcmp0(config, "dhcp"))
		config_type = NET_IP_CONFIG_TYPE_AUTO_IP;
	else if (!g_strcmp0(config, "fixed"))
		config_type = NET_IP_CONFIG_TYPE_FIXED;
	else if (!g_strcmp0(config, "off"))
		config_type = NET_IP_CONFIG_TYPE_OFF;
	else
		config_type = NET_IP_CONFIG_TYPE_DYNAMIC;

	return config_type;
}

char *_wifi_get_ip_config_str(net_ip_config_type_t ip_config_type)
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

wifi_error_e _wifi_connman_lib_error2wifi_error(enum connman_lib_err err_type)
{
	switch (err_type) {
	case CONNMAN_LIB_ERR_NONE:
		return WIFI_ERROR_NONE;
	case CONNMAN_LIB_ERR_ALREADY_EXISTS:
		return WIFI_ERROR_INVALID_OPERATION;
	case CONNMAN_LIB_ERR_NOT_REGISTERED:
		return WIFI_ERROR_INVALID_OPERATION;
	case CONNMAN_LIB_ERR_NOT_CONNECTED:
		return WIFI_ERROR_NO_CONNECTION;
	case CONNMAN_LIB_ERR_ALREADY_CONNECTED:
		return WIFI_ERROR_ALREADY_EXISTS;
	case CONNMAN_LIB_ERR_IN_PROGRESS:
		return WIFI_ERROR_NOW_IN_PROGRESS;
	case CONNMAN_LIB_ERR_OPERATION_ABORTED:
		return WIFI_ERROR_OPERATION_ABORTED;
	case CONNMAN_LIB_ERR_OPERATION_TIMEOUT:
	case CONNMAN_LIB_ERR_TIMEOUT:
		return WIFI_ERROR_NO_REPLY;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}
}

static unsigned int __wifi_essid_strlen(const char *s)
{
	const char *p = s;
	while (*p)
		p++;
	return p - s;
}

static const char *__mode2string(wlan_connection_mode_type_t wlan_mode)
{
	switch (wlan_mode) {
	case NETPM_WLAN_CONNMODE_AUTO:
		break;
	case NETPM_WLAN_CONNMODE_INFRA:
		return "managed";
	case NETPM_WLAN_CONNMODE_ADHOC:
		return "adhoc";
	}

	return NULL;
}

static const char *__security2string(wlan_security_mode_type_t sec_mode)
{
	switch (sec_mode) {
	case WLAN_SEC_MODE_NONE:
		return "none";
	case WLAN_SEC_MODE_WEP:
		return "wep";
	case WLAN_SEC_MODE_WPA_PSK:
	case WLAN_SEC_MODE_WPA2_PSK:
		return "psk";
	case WLAN_SEC_MODE_IEEE8021X:
		return "ieee8021x";
	}

	return NULL;
}

static wifi_security_type_e __string2security(char **security)
{
	wifi_security_type_e sec_mode = WIFI_SECURITY_TYPE_NONE;

	while (*security) {
		WIFI_LOG(WIFI_INFO, "security is %s\n", *security);
		if (!g_strcmp0(*security, "none"))
			sec_mode = WIFI_SECURITY_TYPE_NONE;
		else if (!g_strcmp0(*security, "wep"))
			sec_mode = WIFI_SECURITY_TYPE_WEP;
		else if (!g_strcmp0(*security, "psk"))
			sec_mode = WIFI_SECURITY_TYPE_WPA_PSK;
		else if (!g_strcmp0(*security, "ieee8021x"))
			sec_mode = WIFI_SECURITY_TYPE_EAP;
		else if (!g_strcmp0(*security, "wpa"))
			sec_mode = WIFI_SECURITY_TYPE_WPA_PSK;
		else if (!g_strcmp0(*security, "rsn"))
			sec_mode = WIFI_SECURITY_TYPE_WPA2_PSK;
		else if (!g_strcmp0(*security, "wps")) {
			security++;
			continue;
		} else
			sec_mode = WIFI_SECURITY_TYPE_NONE;

		security++;
	}

	return sec_mode;
}

static char *__create_group(net_profile_info_t *profile_info)
{
	GString *str;
	unsigned int i;
	unsigned int essid_len;

	const char *mode;
	const char *security;

	essid_len = __wifi_essid_strlen(profile_info->essid);
	if (essid_len == 0)
		return NULL;

	str = g_string_sized_new((essid_len * 2) + 24);
	if (!str)
		return NULL;

	if (essid_len > 0 && profile_info->essid[0] != '\0') {
		for (i = 0; i < essid_len; i++)
			g_string_append_printf(str, "%02x",
						profile_info->essid[i]);
	} else
		g_string_append_printf(str, "hidden");

	mode = __mode2string(profile_info->wlan_mode);
	if (mode)
		g_string_append_printf(str, "_%s", mode);

	security = __security2string(profile_info->sec_mode);
	if (security)
		g_string_append_printf(str, "_%s", security);

	return g_string_free(str, FALSE);
}

struct connman_service *__get_connman_service(net_profile_info_t *profile_info)
{
	char *grp_name;
	const char *path;
	GList *iter;
	GList *connman_services_list = NULL;

	WIFI_LOG(WIFI_INFO, "%s\n", profile_info->essid);
	WIFI_LOG(WIFI_INFO, "%d\n", profile_info->sec_mode);

	grp_name = __create_group(profile_info);
	if (grp_name == NULL)
		return NULL;

	WIFI_LOG(WIFI_INFO, "grp_name is %s\n", grp_name);

	connman_services_list = connman_get_services();

	for (iter = connman_services_list; iter != NULL; iter = iter->next) {
		struct connman_service *service =
			(struct connman_service *)(iter->data);
		path = connman_service_get_path(service);

		if (g_str_has_suffix(path, grp_name)) {
			g_free(profile_info->profile_name);
			profile_info->profile_name = g_strdup(path);
			return service;
		}
	}

	return NULL;
}

static void __libnet_set_connected_cb(wifi_connected_cb user_cb,
						void *user_data)
{
	if (user_cb) {
		wifi_callbacks.connected_cb = user_cb;
		wifi_callbacks.connected_user_data = user_data;
	}
}

static void __libnet_connected_cb(wifi_error_e result)
{
	if (wifi_callbacks.connected_cb)
		wifi_callbacks.connected_cb(result,
				wifi_callbacks.connected_user_data);

	wifi_callbacks.connected_cb = NULL;
	wifi_callbacks.connected_user_data = NULL;
}

static void __libnet_set_disconnected_cb(wifi_disconnected_cb user_cb,
							void *user_data)
{
	if (user_cb) {
		wifi_callbacks.disconnected_cb = user_cb;
		wifi_callbacks.disconnected_user_data = user_data;
	}
}

static void __libnet_disconnected_cb(wifi_error_e result)
{
	if (wifi_callbacks.disconnected_cb)
		wifi_callbacks.disconnected_cb(result,
				wifi_callbacks.disconnected_user_data);

	wifi_callbacks.disconnected_cb = NULL;
	wifi_callbacks.disconnected_user_data = NULL;
}

static void connman_service_connect_cb(enum connman_lib_err result,
				       void *user_data)
{
	WIFI_LOG(WIFI_INFO, "callback: %d\n", result);

	__libnet_connected_cb(_wifi_connman_lib_error2wifi_error(result));
}

static void connman_service_disconnect_cb(enum connman_lib_err result,
					  void *user_data)
{
	WIFI_LOG(WIFI_INFO, "callback: %d\n", result);

	__libnet_disconnected_cb(_wifi_connman_lib_error2wifi_error(result));
}

static int __net_dbus_set_agent_passphrase(const char *path,
						 const char *passphrase)
{
	int rv;
	char *service_id;

	if (NULL == passphrase || strlen(passphrase) <= 0) {
		WIFI_LOG(WIFI_ERROR, "Invalid param \n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	service_id = g_strrstr(path, "/") + 1;
	rv = winet_wifi_update_agent_passphrase(service_id, passphrase);
	if (rv != 0) {
		WIFI_LOG(WIFI_ERROR,
			"winet_wifi_update_agent_passphrase failed. Error=%d\n",
			rv);
		return WIFI_ERROR_OPERATION_FAILED;
	}

	WIFI_LOG(WIFI_ERROR, "Successfully sent passphrase\n");

	return WIFI_ERROR_NONE;
}

static int __net_dbus_connect_service(wifi_ap_h ap_h,
		const net_wifi_connect_service_info_t *wifi_connection_info)
{
	int rv = WIFI_ERROR_NONE;
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;

	struct connman_service *service = _wifi_get_service_h(ap_h);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	if (g_strcmp0(wifi_connection_info->security, "ieee8021x") == 0) {
		/* Create the EAP config file
		 * TODO:
		 */
		/*_net_dbus_set_eap_config_fields(wifi_connection_info);*/
		if (rv != WIFI_ERROR_NONE) {
			WIFI_LOG(WIFI_ERROR, "Fail to create eap_config\n");

			goto done;
		}
	} else if (g_strcmp0(wifi_connection_info->security, "none") != 0) {
		rv = __net_dbus_set_agent_passphrase(
				connman_service_get_path(service),
				wifi_connection_info->passphrase);
		if (rv != WIFI_ERROR_NONE) {
			WIFI_LOG(WIFI_ERROR, "Fail to set agent_passphrase\n");

			goto done;
		}
	}

	err = connman_service_connect(service, connman_service_connect_cb,
									NULL);
	rv = _wifi_connman_lib_error2wifi_error(err);

done:
	return rv;
}

/** This function is used only to open Wi-Fi connection with hidden APs */
static int __net_open_connection_with_wifi_info(wifi_ap_h ap_h,
				const net_wifi_connection_info_t* wifi_info)
{
	int rv = WIFI_ERROR_NONE;
	net_wifi_connect_service_info_t wifi_connection_info;
	memset(&wifi_connection_info, 0,
			sizeof(net_wifi_connect_service_info_t));

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
				g_strdup(wifi_info->
				security_info.authentication.wep.wepKey);
		break;

	/** WPA-PSK(equivalent to WPA-NONE in case of Ad-Hoc) */
	case WLAN_SEC_MODE_WPA_PSK:
		wifi_connection_info.security = g_strdup("psk");
		wifi_connection_info.passphrase =
				g_strdup(wifi_info->
				security_info.authentication.psk.pskKey);
		break;

	/** WPA2-PSK */
	/** WPA-PSK / WPA2-PSK supported */
	case WLAN_SEC_MODE_WPA2_PSK:
		wifi_connection_info.security = g_strdup("rsn");
		wifi_connection_info.passphrase =
				g_strdup(wifi_info->
				security_info.authentication.psk.pskKey);
		break;

	case WLAN_SEC_MODE_IEEE8021X:
		break;
	default:
		WIFI_LOG(WIFI_ERROR, "Invalid security type\n");

		rv = WIFI_ERROR_INVALID_OPERATION;
		goto done;
	}

	rv = __net_dbus_connect_service(ap_h, &wifi_connection_info);
	if (rv != WIFI_ERROR_NONE)
		WIFI_LOG(WIFI_ERROR,
			"Failed to request connect service. Error [%d]\n", rv);
	else
		WIFI_LOG(WIFI_ERROR,
				"Successfully requested to connect service\n");

done:
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

	return rv;
}

static int __libnet_connect_with_wifi_info(wifi_ap_h ap_h,
				wifi_connected_cb callback, void *user_data)
{
	net_wifi_connection_info_t *wifi_info;

	wifi_info = _wifi_get_conn_info();

	return __net_open_connection_with_wifi_info(ap_h, wifi_info);
}

static void __libnet_set_scan_request_cb(wifi_disconnected_cb user_cb,
							void *user_data)
{
	if (user_cb) {
		wifi_callbacks.scan_request_cb = user_cb;
		wifi_callbacks.scan_request_user_data = user_data;
	}
}

static wifi_connection_state_e connection_state_string2type(const char *str)
{
	if (strcmp(str, "idle") == 0)
		return WIFI_CONNECTION_STATE_DISCONNECTED;
	if (strcmp(str, "association") == 0)
		return WIFI_CONNECTION_STATE_ASSOCIATION;
	if (strcmp(str, "configuration") == 0)
		return WIFI_CONNECTION_STATE_CONFIGURATION;
	if (strcmp(str, "ready") == 0)
		return WIFI_CONNECTION_STATE_CONNECTED;
	if (strcmp(str, "online") == 0)
		return WIFI_CONNECTION_STATE_CONNECTED;
	if (strcmp(str, "disconnect") == 0)
		return WIFI_CONNECTION_STATE_DISCONNECTED;
	if (strcmp(str, "failure") == 0)
		return WIFI_CONNECTION_STATE_DISCONNECTED;

	return -1;
}

static void service_state_changed(struct connman_service *service,
							void *user_data)
{
	const char *name = connman_service_get_name(service);
	const char *new_state = connman_service_get_state(service);
	char **security = connman_service_get_security(service);

	WIFI_LOG(WIFI_INFO, "name %s, state, %s", name, new_state);

	if (wifi_callbacks.connection_state_cb) {
		wifi_connection_state_e state =
				connection_state_string2type(new_state);
		wifi_ap_h ap;

		wifi_ap_create(name, &ap);
		wifi_ap_set_security_type(ap,
					__string2security(security));

		wifi_callbacks.connection_state_cb(state,
				ap,
				wifi_callbacks.connection_state_user_data);

		wifi_ap_destroy(ap);
	}
}

static void unregister_service_monitor(gpointer data, gpointer user_data)
{
	struct connman_service *service = data;

	const char *path = connman_service_get_path(service);
	const char *type = connman_service_get_type(service);

	WIFI_LOG(WIFI_INFO, "path %s, type %s", path, type);

	if (strcmp(type, "wifi") != 0)
		return;

	connman_service_unset_property_changed_cb(service, SERVICE_PROP_STATE);
}

static void register_service_monitor(gpointer data, gpointer user_data)
{
	struct connman_service *service = data;

	const char *path = connman_service_get_path(service);
	const char *type = connman_service_get_type(service);

	WIFI_LOG(WIFI_INFO, "path %s, type %s", path, type);

	if (strcmp(type, "wifi") != 0)
		return;

	connman_service_set_property_changed_cb(service, SERVICE_PROP_STATE,
						service_state_changed,
						user_data);
}

static void unregister_all_serivces_monitor()
{
	GList *services;

	services = connman_get_services();

	g_list_foreach(services, unregister_service_monitor, NULL);
}

static void register_all_serivces_monitor()
{
	GList *services;

	services = connman_get_services();

	g_list_foreach(services, register_service_monitor, NULL);
}

static void service_changed_callback(struct connman_manager *manager,
				     GList *added_service_list,
				     GList *all_services_list,
				     void *user_data)
{
	WIFI_LOG(WIFI_INFO, "service changed");

	if (wifi_callbacks.connection_state_cb)
		register_all_serivces_monitor();
}

static void technology_powered_changed(
					struct connman_technology *technology,
					void *user_data)
{
	gboolean powered = connman_get_technology_powered(technology);
	enum connman_technology_type type =
				connman_get_technology_type(technology);

	WIFI_LOG(WIFI_INFO, "technology %d powered %d", type, powered);

	if (wifi_callbacks.device_state_cb) {
		wifi_device_state_e state;

		state = powered ? WIFI_DEVICE_STATE_ACTIVATED :
						WIFI_DEVICE_STATE_DEACTIVATED;
		wifi_callbacks.device_state_cb(state,
					wifi_callbacks.device_state_user_data);
	}
}

static void technology_added_callback(
				struct connman_technology *technology,
				void *user_data)
{
	enum connman_technology_type type =
				connman_get_technology_type(technology);

	WIFI_LOG(WIFI_INFO, "technology %d added", type);

	if (type == TECH_TYPE_WIFI && wifi_callbacks.device_state_cb)
		connman_technology_set_property_changed_cb(technology,
						TECH_PROP_POWERED,
						technology_powered_changed,
						user_data);
}

static void __wifi_set_technology_power_changed_cb()
{
	struct connman_technology *technology;

	technology = connman_get_technology(TECH_TYPE_WIFI);
	if (technology)
		connman_technology_set_property_changed_cb(technology,
						TECH_PROP_POWERED,
						technology_powered_changed,
						NULL);
}

static void __wifi_unset_technology_power_changed_cb()
{
	struct connman_technology *technology;

	technology = connman_get_technology(TECH_TYPE_WIFI);
	if (technology)
		connman_technology_unset_property_changed_cb(technology,
						TECH_PROP_POWERED);
}

static void __wifi_set_service_connection_changed_cb()
{
	register_all_serivces_monitor();
}

static void __wifi_unset_service_connection_changed_cb()
{
	unregister_all_serivces_monitor();
}

bool _wifi_libnet_init(void)
{
	int rv;

	rv = connman_lib_init();

	if (rv != 0)
		return false;

	connman_set_services_changed_cb(service_changed_callback, NULL);

	connman_set_technology_added_cb(technology_added_callback, NULL);

	return true;
}

bool _wifi_libnet_deinit(void)
{
	g_slist_free_full(ap_handle_list, g_free);
	ap_handle_list = NULL;
	memset(&wifi_callbacks, 0, sizeof(struct _wifi_cb_s));
	connman_lib_deinit();
	return true;
}

int _wifi_activate(wifi_activated_cb callback, void *user_data)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;
	struct connman_technology *technology =
					connman_get_technology(TECH_TYPE_WIFI);
	if (!technology)
		return WIFI_ERROR_INVALID_OPERATION;

	winet_wifi_set_work_mode(WIFI_WORK_MODE_STATION);

	err = connman_enable_technology(technology);
	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;
}

int _wifi_deactivate(wifi_deactivated_cb callback, void *user_data)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;
	struct connman_technology *technology =
					connman_get_technology(TECH_TYPE_WIFI);
	if (!technology)
		return WIFI_ERROR_INVALID_OPERATION;

	err = connman_disable_technology(technology);
	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	winet_wifi_set_work_mode(WIFI_WORK_MODE_OFF);

	return WIFI_ERROR_NONE;
}

bool _wifi_libnet_check_ap_validity(wifi_ap_h ap_h)
{
	GSList *iter;

	for (iter = ap_handle_list; iter != NULL; iter = iter->next) {
		if (ap_h == iter->data)
			return true;
	}

	return false;
}

void _wifi_libnet_add_to_ap_list(wifi_ap_h ap_h)
{
	ap_handle_list = g_slist_append(ap_handle_list, ap_h);
}

void _wifi_libnet_remove_from_ap_list(wifi_ap_h ap_h)
{
	net_profile_info_t *ap_info = ap_h;
	ap_handle_list = g_slist_remove(ap_handle_list, ap_info);
	g_free(ap_info->profile_name);
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
			WIFI_LOG(WIFI_ERROR, "Profile name is invalid\n");
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
	if (!technology)
		return false;

	powered = connman_get_technology_powered(technology);

	if (powered)
		*device_state = WIFI_DEVICE_STATE_ACTIVATED;
	else
		*device_state = WIFI_DEVICE_STATE_DEACTIVATED;

	WIFI_LOG(WIFI_ERROR, "Wi-Fi device state: %d", *device_state);

	return true;
}

bool _wifi_libnet_get_wifi_state(wifi_connection_state_e *connection_state)
{
	struct connman_technology *technology;
	gboolean wifi_powered;
	GList *services;
	GList *list;

	technology = connman_get_technology(TECH_TYPE_WIFI);
	if (!technology)
		return false;

	wifi_powered = connman_get_technology_powered(technology);

	if (!wifi_powered) {
		*connection_state = WIFI_CONNECTION_STATE_DISCONNECTED;
		return true;
	}

	services = connman_get_services();
	if (services == NULL) {
		*connection_state = WIFI_CONNECTION_STATE_DISCONNECTED;
		return true;
	}

	list = services;

	WIFI_LOG(WIFI_INFO, "list: %p", list);
	WIFI_LOG(WIFI_INFO, "services: %p", services);

	while (list != NULL) {
		wifi_connection_state_e state;
		struct connman_service *service;
		const char *str;
		const char *type;

		service = list->data;
		str = connman_service_get_state(service);
		state = connection_state_string2type(str);
		type = connman_service_get_type(service);

		WIFI_LOG(WIFI_INFO, "type: %s, state %s", type, str);

		if (state > WIFI_CONNECTION_STATE_DISCONNECTED &&
			strcmp(type, "wifi") == 0) {
			*connection_state = state;
			return true;
		}

		list = g_list_next(list);
		WIFI_LOG(WIFI_INFO, "list: %p, services %p", list, services);
	}

	*connection_state = WIFI_CONNECTION_STATE_DISCONNECTED;
	return true;
}

int _wifi_libnet_get_intf_name(char** name)
{
	return WIFI_ERROR_NONE;
}

int _wifi_libnet_scan_request(wifi_scan_finished_cb callback,
						void *user_data)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;
	struct connman_technology *technology =
				connman_get_technology(TECH_TYPE_WIFI);
	if (!technology)
		return WIFI_ERROR_INVALID_OPERATION;

	__libnet_set_scan_request_cb(callback, user_data);

	err = connman_scan_technology(technology);
	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_scan_hidden_ap(const char *essid,
				wifi_scan_finished_cb callback,
				void *user_data)
{
	int rv = WIFI_ERROR_NONE;
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;
	/*err = net_specific_scan_wifi(essid);*/

	if (err == CONNMAN_LIB_ERR_NONE) {
		wifi_callbacks.scan_hidden_ap_cb = callback;
		wifi_callbacks.scan_hidden_ap_user_data = user_data;
		rv = WIFI_ERROR_NONE;
	} else {
		rv = _wifi_connman_lib_error2wifi_error(err);
	}

	return rv;
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
		state_type = _wifi_get_service_state_type(state);
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
				g_strdup(connman_service_get_name(ap_h));

	_wifi_libnet_add_to_ap_list(*ap);

	return WIFI_ERROR_NONE;
}

bool _wifi_libnet_foreach_found_aps(wifi_found_ap_cb callback,
							void *user_data)
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
		struct connman_service *service = iter->data;
		if (!g_strcmp0(connman_service_get_type(service), "wifi")) {
			wifi_ap_h ap;
			const char *essid = connman_service_get_name(service);
			char **security = connman_service_get_security(service);

			WIFI_LOG(WIFI_INFO, "essid is %s", essid);

			wifi_ap_create(essid, &ap);
			wifi_ap_set_security_type(ap,
						__string2security(security));
			rv = callback(ap, user_data);
			if (rv == false)
				break;
		}
	}

	return true;
}

bool _wifi_libnet_foreach_found_hidden_aps(wifi_found_ap_cb callback,
						void *user_data)
{
	return true;
}

int _wifi_libnet_open_profile(wifi_ap_h ap_h, wifi_connected_cb callback,
							void *user_data)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;
	struct connman_service *service = _wifi_get_service_h(ap_h);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	__libnet_set_connected_cb(callback, user_data);

	if (connman_service_get_favorite(service))
		err = connman_service_connect(service,
					connman_service_connect_cb, NULL);
	else
		return __libnet_connect_with_wifi_info(ap_h, callback,
								user_data);

	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;

}

int _wifi_libnet_close_profile(wifi_ap_h ap_h,
			wifi_disconnected_cb callback, void *user_data)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;
	struct connman_service *service = _wifi_get_service_h(ap_h);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	__libnet_set_disconnected_cb(callback, user_data);
	err = connman_service_disconnect(service,
				connman_service_disconnect_cb, NULL);
	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_connect_with_wps(wifi_ap_h ap_h,
				wifi_connected_cb callback, void *user_data)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;
	struct connman_service *service = _wifi_get_service_h(ap_h);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	__libnet_set_connected_cb(callback, user_data);

	if (connman_service_get_favorite(service))
		err = connman_service_connect(service,
					connman_service_connect_cb, NULL);
	else
		return __libnet_connect_with_wifi_info(ap_h, callback,
								user_data);

	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;
}

int _wifi_libnet_forget_ap(wifi_ap_h ap_h)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;
	struct connman_service *service = _wifi_get_service_h(ap_h);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	err = connman_service_remove(service);
	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;
}

int _wifi_set_power_on_off_cb(wifi_device_state_changed_cb callback,
							void *user_data)
{
	if (wifi_callbacks.device_state_cb)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.device_state_cb = callback;
	wifi_callbacks.device_state_user_data = user_data;

	__wifi_set_technology_power_changed_cb();

	return WIFI_ERROR_NONE;
}

int _wifi_unset_power_on_off_cb(void)
{
	if (wifi_callbacks.device_state_cb == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.device_state_cb = NULL;
	wifi_callbacks.device_state_user_data = NULL;

	__wifi_unset_technology_power_changed_cb();

	return WIFI_ERROR_NONE;
}

int _wifi_set_background_scan_cb(wifi_scan_finished_cb callback,
							void *user_data)
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

int _wifi_set_connection_state_cb(
		wifi_connection_state_changed_cb callback, void *user_data)
{
	if (wifi_callbacks.connection_state_cb)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.connection_state_cb = callback;
	wifi_callbacks.connection_state_user_data = user_data;

	__wifi_set_service_connection_changed_cb();

	return WIFI_ERROR_NONE;
}

int _wifi_unset_connection_state_cb()
{
	if (wifi_callbacks.connection_state_cb == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	wifi_callbacks.connection_state_cb = NULL;
	wifi_callbacks.connection_state_user_data = NULL;

	__wifi_unset_service_connection_changed_cb();

	return WIFI_ERROR_NONE;
}

struct connman_service *_wifi_get_service_h(wifi_ap_h ap_h)
{
	struct connman_service *service;

	net_profile_info_t *profile_info = ap_h;
	if (profile_info->profile_name == NULL)
		service = __get_connman_service(profile_info);
	else
		service = connman_get_service(profile_info->profile_name);

	return service;
}
