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
#include <arpa/inet.h>
#include <glib.h>

#include <connman-service.h>

#include "wifi-internal.h"

static void convert_wifi_security(wlan_security_info_t *security_info,
							char **security)
{
	while (*security) {
		if (g_strcmp0(*security, "none") == 0 &&
		    security_info->sec_mode < WLAN_SEC_MODE_NONE)
			security_info->sec_mode = WLAN_SEC_MODE_NONE;
		else if (!g_strcmp0(*security, "wep"))
			security_info->sec_mode = WLAN_SEC_MODE_WEP;
		else if (!g_strcmp0(*security, "psk"))
			security_info->sec_mode = WLAN_SEC_MODE_WPA_PSK;
		else if (!g_strcmp0(*security, "ieee8021x"))
			security_info->sec_mode = WLAN_SEC_MODE_IEEE8021X;
		else if (!g_strcmp0(*security, "wpa"))
			security_info->sec_mode = WLAN_SEC_MODE_WPA_PSK;
		else if (!g_strcmp0(*security, "rsn"))
			security_info->sec_mode = WLAN_SEC_MODE_WPA2_PSK;
		else if (!g_strcmp0(*security, "wps"))
			security_info->wps_support = TRUE;
		else
			security_info->sec_mode = WLAN_SEC_MODE_NONE;

		security++;
	}

}

static void __wifi_init_ap(net_profile_info_t *profile_info,
							const char *bssid)
{
	profile_info->bssid = g_strdup(bssid);
	profile_info->proxy_type = WIFI_PROXY_TYPE_AUTO;
}

wifi_connection_state_e _wifi_convert_to_ap_state(
				net_state_type_t state)
{
	wifi_connection_state_e ap_state;

	switch (state) {
	case NET_STATE_TYPE_ONLINE:
	case NET_STATE_TYPE_READY:
		ap_state = WIFI_CONNECTION_STATE_CONNECTED;
		break;
	case NET_STATE_TYPE_IDLE:
	case NET_STATE_TYPE_FAILURE:
	case NET_STATE_TYPE_DISCONNECT:
		ap_state = WIFI_CONNECTION_STATE_DISCONNECTED;
		break;
	case NET_STATE_TYPE_ASSOCIATION:
		ap_state = WIFI_CONNECTION_STATE_ASSOCIATION;
		break;
	case NET_STATE_TYPE_CONFIGURATION:
		ap_state = WIFI_CONNECTION_STATE_CONFIGURATION;
		break;
	default:
		ap_state = -1;
		break;
	}

	return ap_state;
}

/* Wi-Fi AP ******************************************************************/
EXPORT_API int wifi_ap_create(const char* bssid, wifi_ap_h* ap)
{
	if (bssid == NULL || ap == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *ap_info =
				g_try_malloc0(sizeof(net_profile_info_t));
	if (ap_info == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	__wifi_init_ap(ap_info, bssid);

	_wifi_libnet_add_to_ap_list((wifi_ap_h)ap_info);
	*ap = (wifi_ap_h)ap_info;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_destroy(wifi_ap_h ap)
{
	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	_wifi_libnet_remove_from_ap_list(ap);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_clone(wifi_ap_h* cloned_ap, wifi_ap_h origin)
{
	if (_wifi_libnet_check_ap_validity(origin) == false ||
						cloned_ap == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *ap_info =
				g_try_malloc0(sizeof(net_profile_info_t));
	if (ap_info == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	memcpy(ap_info, origin, sizeof(net_profile_info_t));

	_wifi_libnet_add_to_ap_list((wifi_ap_h)ap_info);
	*cloned_ap = (wifi_ap_h)ap_info;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_refresh(wifi_ap_h ap)
{
	return WIFI_ERROR_NONE;
}

/* Wi-Fi network information *************************************************/
EXPORT_API int wifi_ap_get_essid(wifi_ap_h ap, char** essid)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || essid == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	const gchar *service_essid = connman_service_get_name(service);
	if (service_essid == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	*essid = g_strdup(service_essid);
	if (*essid == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_bssid(wifi_ap_h ap, char** bssid)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || bssid == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	const gchar *service_bssid = connman_service_get_bssid(service);
	if (service_bssid == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	*bssid = g_strdup(service_bssid);
	if (*bssid == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_rssi(wifi_ap_h ap, int* rssi)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || rssi == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	*rssi = connman_service_get_strength(service);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_frequency(wifi_ap_h ap, int* frequency)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || frequency == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	*frequency = connman_service_get_frequency(service);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_max_speed(wifi_ap_h ap, int* max_speed)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || max_speed == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	*max_speed = connman_service_get_max_rate(service);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_is_favorite(wifi_ap_h ap, bool* favorite)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || favorite == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	*favorite = connman_service_get_favorite(service);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_connection_state(wifi_ap_h ap,
					wifi_connection_state_e* state)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || state == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_state_type_t state_type;

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	state_type = _wifi_get_service_state_type(
					connman_service_get_state(service));

	*state = _wifi_convert_to_ap_state(state_type);

	if (*state < 0)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_ip_config_type(wifi_ap_h ap,
				wifi_address_family_e address_family,
				wifi_ip_config_type_e* type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	const struct service_ipv4 *ipv4_config;
	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	ipv4_config = connman_service_get_ipv4_config(service);

	switch (_wifi_get_ip_config_type(ipv4_config->method)) {
	case NET_IP_CONFIG_TYPE_STATIC:
		*type = WIFI_IP_CONFIG_TYPE_STATIC;
		break;
	case NET_IP_CONFIG_TYPE_DYNAMIC:
		*type = WIFI_IP_CONFIG_TYPE_DYNAMIC;
		break;
	case NET_IP_CONFIG_TYPE_AUTO_IP:
		*type = WIFI_IP_CONFIG_TYPE_AUTO;
		break;
	case NET_IP_CONFIG_TYPE_FIXED:
		*type = WIFI_IP_CONFIG_TYPE_FIXED;
		break;
	case NET_IP_CONFIG_TYPE_OFF:
		*type = WIFI_IP_CONFIG_TYPE_NONE;
		break;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_ip_config_type(wifi_ap_h ap,
				wifi_address_family_e address_family,
				wifi_ip_config_type_e type)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6)) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	net_ip_config_type_t ip_config_type;

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	switch (type) {
	case WIFI_IP_CONFIG_TYPE_STATIC:
		ip_config_type = NET_IP_CONFIG_TYPE_STATIC;
		break;
	case WIFI_IP_CONFIG_TYPE_DYNAMIC:
		ip_config_type = NET_IP_CONFIG_TYPE_DYNAMIC;
		break;
	case WIFI_IP_CONFIG_TYPE_AUTO:
		ip_config_type = NET_IP_CONFIG_TYPE_AUTO_IP;
		break;
	case WIFI_IP_CONFIG_TYPE_FIXED:
		ip_config_type = NET_IP_CONFIG_TYPE_FIXED;
		break;
	case WIFI_IP_CONFIG_TYPE_NONE:
		ip_config_type = NET_IP_CONFIG_TYPE_OFF;
		break;
	default:
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct service_ipv4 ipv4_config;
	memset(&ipv4_config, 0, sizeof(struct service_ipv4));
	ipv4_config.method = _wifi_get_ip_config_str(ip_config_type);

	err = connman_service_set_ipv4_config(service, &ipv4_config);

	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_ip_address(wifi_ap_h ap,
				wifi_address_family_e address_family,
				char** ip_address)
{
	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    ip_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	const struct service_ipv4 *ipv4;
	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	ipv4 = connman_service_get_ipv4_info(service);
	if (ipv4->address == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	*ip_address = g_strdup(ipv4->address);
	if (*ip_address == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_ip_address(wifi_ap_h ap,
				wifi_address_family_e address_family,
				const char* ip_address)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6)) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	struct service_ipv4 ipv4_config;
	memset(&ipv4_config, 0, sizeof(struct service_ipv4));
	ipv4_config.method = "manual";
	ipv4_config.address = g_strdup(ip_address);

	err = connman_service_set_ipv4_config(service, &ipv4_config);

	g_free(ipv4_config.address);

	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_subnet_mask(wifi_ap_h ap,
				wifi_address_family_e address_family,
				char** subnet_mask)
{
	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    subnet_mask == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	const struct service_ipv4 *ipv4;
	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	ipv4 = connman_service_get_ipv4_info(service);
	if (ipv4->netmask == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	*subnet_mask = g_strdup(ipv4->netmask);
	if (*subnet_mask == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_subnet_mask(wifi_ap_h ap,
				wifi_address_family_e address_family,
				const char* subnet_mask)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6)) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	struct service_ipv4 ipv4_config;
	memset(&ipv4_config, 0, sizeof(struct service_ipv4));
	ipv4_config.method = "manual";
	ipv4_config.netmask = g_strdup(subnet_mask);

	err = connman_service_set_ipv4_config(service, &ipv4_config);

	g_free(ipv4_config.netmask);

	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_gateway_address(wifi_ap_h ap,
				wifi_address_family_e address_family,
				char** gateway_address)
{
	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    gateway_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	const struct service_ipv4 *ipv4;
	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	ipv4 = connman_service_get_ipv4_info(service);
	if (ipv4->gateway == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	*gateway_address = g_strdup(ipv4->gateway);
	if (*gateway_address == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_gateway_address(wifi_ap_h ap,
				wifi_address_family_e address_family,
				const char* gateway_address)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6)) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	struct service_ipv4 ipv4_config;
	memset(&ipv4_config, 0, sizeof(struct service_ipv4));
	ipv4_config.method = "manual";
	ipv4_config.gateway = g_strdup(gateway_address);

	err = connman_service_set_ipv4_config(service, &ipv4_config);

	g_free(ipv4_config.gateway);

	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_proxy_address(wifi_ap_h ap,
				wifi_address_family_e address_family,
				char** proxy_address)
{
	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    proxy_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	const struct service_proxy *proxy;
	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	proxy = connman_service_get_proxy_info(service);
	if(proxy->method == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	net_proxy_type_t proxy_type = _wifi_get_proxy_type(proxy->method);

	if(proxy_type == NET_PROXY_TYPE_AUTO && proxy->url != NULL)
		*proxy_address = g_strdup(proxy->url);
	else if(proxy_type == NET_PROXY_TYPE_MANUAL && proxy->servers != NULL)
		*proxy_address = g_strdup(proxy->servers[0]);
	else
		return WIFI_ERROR_INVALID_OPERATION;

	if(*proxy_address == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_proxy_address(wifi_ap_h ap,
				wifi_address_family_e address_family,
				const char* proxy_address)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6)) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	struct service_proxy proxy_config;
	memset(&proxy_config, 0, sizeof(struct service_proxy));

	proxy_config.servers = g_try_malloc0(sizeof(char*));

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	if (((net_profile_info_t *) ap)->proxy_type ==
					WIFI_PROXY_TYPE_MANUAL) {
		proxy_config.method = "manual";
		*proxy_config.servers = g_strdup(proxy_address);
		err = connman_service_set_proxy_config(service, &proxy_config);
		g_free(*proxy_config.servers);
		g_free(proxy_config.servers);
	} else if (((net_profile_info_t *) ap)->proxy_type ==
					WIFI_PROXY_TYPE_AUTO) {
		proxy_config.method = "auto";
		proxy_config.url = g_strdup(proxy_address);
		err = connman_service_set_proxy_config(service, &proxy_config);
		g_free(proxy_config.url);
	} else
		return WIFI_ERROR_INVALID_PARAMETER;

	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_proxy_type(wifi_ap_h ap, wifi_proxy_type_e* type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	const struct service_proxy *proxy;
	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	proxy = connman_service_get_proxy_info(service);
	if(proxy->method == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	switch(_wifi_get_proxy_type(proxy->method)) {
		case NET_PROXY_TYPE_DIRECT:
			*type = WIFI_PROXY_TYPE_DIRECT;
			break;
		case NET_PROXY_TYPE_MANUAL:
			*type = WIFI_PROXY_TYPE_MANUAL;
			break;
		case NET_PROXY_TYPE_AUTO:
			*type = WIFI_PROXY_TYPE_AUTO;
			break;
		default:
			return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_proxy_type(wifi_ap_h ap,
					wifi_proxy_type_e proxy_type)
{
	enum connman_lib_err err = CONNMAN_LIB_ERR_NONE;

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct service_proxy proxy_config;
	memset(&proxy_config, 0, sizeof(struct service_proxy));

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	switch (proxy_type) {
	case WIFI_PROXY_TYPE_AUTO:
		proxy_config.method = "auto";
		break;
	case WIFI_PROXY_TYPE_MANUAL:
		proxy_config.method = "manual";
		break;
	case WIFI_PROXY_TYPE_DIRECT:
		proxy_config.method = "direct";
		break;
	}

	if (proxy_type == WIFI_PROXY_TYPE_DIRECT) {
		err = connman_service_set_proxy_config(service, &proxy_config);
	} else {
		((net_profile_info_t *) ap)->proxy_type = proxy_type;
	}

	if (err != CONNMAN_LIB_ERR_NONE)
		return _wifi_connman_lib_error2wifi_error(err);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_dns_address(wifi_ap_h ap, int order,
				wifi_address_family_e address_family,
				char** dns_address)
{
	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    dns_address == NULL ||
	    order <= 0 ||
	    order > NET_DNS_ADDR_MAX) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	bool is_get_dns = false;
	int count = 0;
	char **nameservers = connman_service_get_nameservers(service);
	if (!nameservers)
		return WIFI_ERROR_INVALID_OPERATION;

	while (*nameservers) {
		if (count == (order - 1)) {
			*dns_address = g_strdup(*nameservers);
			if (*dns_address == NULL)
				return WIFI_ERROR_OUT_OF_MEMORY;

			is_get_dns = true;
			break;
		}

		nameservers++;
		count++;
	}

	if (!is_get_dns)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_dns_address(wifi_ap_h ap, int order,
				wifi_address_family_e address_family,
				const char* dns_address)
{
	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    order <= 0 ||
	    order > NET_DNS_ADDR_MAX) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet\n");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	int count = 0;
	char **new_nameservers;
	char **old_nameservers;

	new_nameservers = g_try_new0(char *, NET_DNS_ADDR_MAX + 1);
	old_nameservers = connman_service_get_nameservers(service);
	if (!old_nameservers) {
		new_nameservers[count] = g_strdup(dns_address);
		goto done;
	}

	for (count = 0; count < NET_DNS_ADDR_MAX; count++) {

		if (count == (order - 1)) {
			new_nameservers[count] = g_strdup(dns_address);

			if (*old_nameservers)
				old_nameservers++;

			continue;
		}

		if (*old_nameservers) {
			new_nameservers[count] = g_strdup(*old_nameservers);
			old_nameservers++;
		}
	}

done:
	connman_service_set_nameservers_config(service,
					(const char **) new_nameservers);

	g_strfreev(new_nameservers);

	return WIFI_ERROR_NONE;
}

/* Wi-Fi security information ************************************************/
EXPORT_API int wifi_ap_get_security_type(wifi_ap_h ap,
						wifi_security_type_e* type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	char **security = connman_service_get_security(service);
	if(!security)
		return WIFI_ERROR_INVALID_OPERATION;

	wlan_security_info_t sec_info;
	convert_wifi_security(&sec_info, security);

	switch (sec_info.sec_mode) {
		case WLAN_SEC_MODE_NONE:
			*type = WIFI_SECURITY_TYPE_NONE;
			break;
		case WLAN_SEC_MODE_WEP:
			*type = WIFI_SECURITY_TYPE_WEP;
			break;
		case WLAN_SEC_MODE_WPA_PSK:
			*type = WIFI_SECURITY_TYPE_WPA_PSK;
			break;
		case WLAN_SEC_MODE_WPA2_PSK:
			*type = WIFI_SECURITY_TYPE_WPA2_PSK;
			break;
		case WLAN_SEC_MODE_IEEE8021X:
			*type = WIFI_SECURITY_TYPE_EAP;
			break;
		default:
			return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_security_type(wifi_ap_h ap,
						wifi_security_type_e type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_encryption_type(wifi_ap_h ap,
						wifi_encryption_type_e* type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	const char *encryption_mode;
	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	encryption_mode = connman_service_get_encryption_mode(service);
	if (encryption_mode == NULL)
		return WIFI_ERROR_INVALID_OPERATION;

	switch (_wifi_get_encryption_type(encryption_mode)) {
	case WLAN_ENC_MODE_NONE:
		*type = WIFI_ENCRYPTION_TYPE_NONE;
		break;
	case WLAN_ENC_MODE_WEP:
		*type = WIFI_ENCRYPTION_TYPE_WEP;
		break;
	case WLAN_ENC_MODE_TKIP:
		*type = WIFI_ENCRYPTION_TYPE_TKIP;
		break;
	case WLAN_ENC_MODE_AES:
		*type = WIFI_ENCRYPTION_TYPE_AES;
		break;
	case WLAN_ENC_MODE_TKIP_AES_MIXED:
		*type = WIFI_ENCRYPTION_TYPE_TKIP_AES_MIXED;
		break;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_encryption_type(wifi_ap_h ap,
						wifi_encryption_type_e type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_INVALID_OPERATION;
}

EXPORT_API int wifi_ap_is_passphrase_required(wifi_ap_h ap, bool* required)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || required == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	if (!connman_service_get_passphrase_required(service)) {
		*required = false;
		return WIFI_ERROR_NONE;
	}

	wlan_security_info_t sec_info;
	convert_wifi_security(&sec_info, connman_service_get_security(service));

	switch (sec_info.sec_mode) {
	case WLAN_SEC_MODE_NONE:
	case WLAN_SEC_MODE_IEEE8021X:
		*required = false;
		break;
	case WLAN_SEC_MODE_WEP:
	case WLAN_SEC_MODE_WPA_PSK:
	case WLAN_SEC_MODE_WPA2_PSK:
		*required = true;
		break;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_passphrase(wifi_ap_h ap, const char* passphrase)
{
	if (_wifi_libnet_check_ap_validity(ap) == false ||
							passphrase == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	net_wifi_connection_info_t wifi_conn_info;
	memset(&wifi_conn_info, 0, sizeof(net_wifi_connection_info_t));

	wifi_conn_info.wlan_mode = NETPM_WLAN_CONNMODE_AUTO;

	wlan_security_info_t sec_info;
	convert_wifi_security(&sec_info, connman_service_get_security(service));

	switch (sec_info.sec_mode) {
	case WLAN_SEC_MODE_WEP:
		g_strlcpy(
			wifi_conn_info.security_info.authentication.wep.wepKey,
			passphrase,
			NETPM_WLAN_MAX_WEP_KEY_LEN+1);
		break;
	case WLAN_SEC_MODE_WPA_PSK:
	case WLAN_SEC_MODE_WPA2_PSK:
		g_strlcpy(
			wifi_conn_info.security_info.authentication.psk.pskKey,
			passphrase,
			NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN+1);
		break;
	case WLAN_SEC_MODE_NONE:
	case WLAN_SEC_MODE_IEEE8021X:
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}

	g_strlcpy(
		wifi_conn_info.essid,
		connman_service_get_name(service),
		NET_WLAN_ESSID_LEN + 1);

	wifi_conn_info.security_info.sec_mode = sec_info.sec_mode;

	_wifi_set_conn_info(&wifi_conn_info);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_is_wps_supported(wifi_ap_h ap, bool* supported)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || supported == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	struct connman_service *service = _wifi_get_service_h(ap);
	if (!service)
		return WIFI_ERROR_INVALID_PARAMETER;

	char **security = connman_service_get_security(service);
	if (!security)
		return WIFI_ERROR_INVALID_OPERATION;

	wlan_security_info_t sec_info;
	convert_wifi_security(&sec_info, security);
	if (sec_info.wps_support)
		*supported = true;
	else
		*supported = false;

	return WIFI_ERROR_NONE;
}

/* Wi-Fi EAP *****************************************************************/
EXPORT_API int wifi_ap_set_eap_passphrase(wifi_ap_h ap,
				const char* user_name, const char* password)
{
	if (_wifi_libnet_check_ap_validity(ap) == false ||
				(user_name == NULL && password == NULL)) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_eap_passphrase(wifi_ap_h ap, char** user_name,
						bool* is_password_set)
{
	if (_wifi_libnet_check_ap_validity(ap) == false ||user_name == NULL ||
					is_password_set == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_eap_ca_cert_file(wifi_ap_h ap, char** file)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_eap_ca_cert_file(wifi_ap_h ap, const char* file)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_eap_client_cert_file(wifi_ap_h ap, char** file)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_eap_client_cert_file(wifi_ap_h ap,
							const char* file)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_eap_private_key_file(wifi_ap_h ap, char** file)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_eap_private_key_info(wifi_ap_h ap,
				const char* file, const char* password)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_eap_type(wifi_ap_h ap, wifi_eap_type_e* type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_eap_type(wifi_ap_h ap, wifi_eap_type_e type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_eap_auth_type(wifi_ap_h ap,
						wifi_eap_auth_type_e* type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_eap_auth_type(wifi_ap_h ap,
						wifi_eap_auth_type_e type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}
