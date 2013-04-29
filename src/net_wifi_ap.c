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
#include <arpa/inet.h>
#include <glib.h>
#include "net_wifi_private.h"


static char* __ap_convert_ip_to_string(net_addr_t *ip_addr)
{
	unsigned char *ipaddr = (unsigned char *)&ip_addr->Data.Ipv4.s_addr;

	char *ipstr = g_try_malloc0(16);
	if (ipstr == NULL)
		return NULL;

	snprintf(ipstr, 16, "%d.%d.%d.%d", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);

	return ipstr;
}

static void __wifi_init_ap(net_profile_info_t *profile_info, const char *essid)
{
	profile_info->profile_type = NET_DEVICE_WIFI;
	profile_info->ProfileState = NET_STATE_TYPE_IDLE;
	profile_info->ProfileInfo.Wlan.net_info.IpConfigType = NET_IP_CONFIG_TYPE_OFF;
	profile_info->ProfileInfo.Wlan.net_info.ProxyMethod = NET_PROXY_TYPE_DIRECT;
	profile_info->ProfileInfo.Wlan.wlan_mode = NETPM_WLAN_CONNMODE_AUTO;
	profile_info->ProfileInfo.Wlan.security_info.sec_mode = WLAN_SEC_MODE_NONE;
	profile_info->ProfileInfo.Wlan.security_info.enc_mode = WLAN_ENC_MODE_NONE;
	g_strlcpy(profile_info->ProfileInfo.Wlan.essid, essid, NET_WLAN_ESSID_LEN+1);
}

wifi_connection_state_e _wifi_convert_to_ap_state(net_state_type_t state)
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
	}

	return ap_state;
}

/* Wi-Fi AP module ********************************************************************************/

int wifi_ap_create(const char* essid, wifi_ap_h* ap)
{
	if (essid == NULL || ap == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *ap_info = g_try_malloc0(sizeof(net_profile_info_t));
	if (ap_info == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	__wifi_init_ap(ap_info, essid);

	_wifi_libnet_add_to_ap_list((wifi_ap_h)ap_info);
	*ap = (wifi_ap_h)ap_info;

	return WIFI_ERROR_NONE;
}

int wifi_ap_destroy(wifi_ap_h ap)
{
	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	_wifi_libnet_remove_from_ap_list(ap);

	return WIFI_ERROR_NONE;
}

int wifi_ap_clone(wifi_ap_h* cloned_ap, wifi_ap_h origin)
{
	if (_wifi_libnet_check_ap_validity(origin) == false || cloned_ap == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *ap_info = g_try_malloc0(sizeof(net_profile_info_t));
	if (ap_info == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	memcpy(ap_info, origin, sizeof(net_profile_info_t));

	_wifi_libnet_add_to_ap_list((wifi_ap_h)ap_info);
	*cloned_ap = (wifi_ap_h)ap_info;

	return WIFI_ERROR_NONE;
}

int wifi_ap_refresh(wifi_ap_h ap)
{
	net_profile_info_t ap_info_local;
	net_profile_info_t *ap_info = ap;

	if (net_get_profile_info(ap_info->ProfileName, &ap_info_local) != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Error!!! net_get_profile_info() failed\n");
		return WIFI_ERROR_OPERATION_FAILED;
	}

	memcpy(ap, &ap_info_local, sizeof(net_profile_info_t));

	return WIFI_ERROR_NONE;
}

/* Wi-Fi network information module ***************************************************************/

int wifi_ap_get_essid(wifi_ap_h ap, char** essid)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || essid == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	*essid = g_strdup(profile_info->ProfileInfo.Wlan.essid);
	if (*essid == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_bssid(wifi_ap_h ap, char** bssid)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || bssid == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	*bssid = g_strdup(profile_info->ProfileInfo.Wlan.bssid);
	if (*bssid == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_rssi(wifi_ap_h ap, int* rssi)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || rssi == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	*rssi = (int)profile_info->ProfileInfo.Wlan.Strength;

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_frequency(wifi_ap_h ap, int* frequency)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || frequency == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	*frequency = (int)profile_info->ProfileInfo.Wlan.frequency;

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_max_speed(wifi_ap_h ap, int* max_speed)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || max_speed == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	*max_speed = (int)profile_info->ProfileInfo.Wlan.max_rate / 1000000;

	return WIFI_ERROR_NONE;
}

int wifi_ap_is_favorite(wifi_ap_h ap, bool* favorite)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || favorite == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (profile_info->Favourite)
		*favorite = true;
	else
		*favorite = false;

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_connection_state(wifi_ap_h ap, wifi_connection_state_e* state)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || state == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	*state = _wifi_convert_to_ap_state(profile_info->ProfileState);

	if (*state < 0)
		return WIFI_ERROR_OPERATION_FAILED;

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_ip_config_type(wifi_ap_h ap, wifi_address_family_e address_family, wifi_ip_config_type_e* type)
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

	net_profile_info_t *profile_info = ap;

	switch (profile_info->ProfileInfo.Wlan.net_info.IpConfigType) {
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

int wifi_ap_set_ip_config_type(wifi_ap_h ap, wifi_address_family_e address_family, wifi_ip_config_type_e type)
{
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

	net_profile_info_t *profile_info = ap;

	switch (type) {
	case WIFI_IP_CONFIG_TYPE_STATIC:
		profile_info->ProfileInfo.Wlan.net_info.IpConfigType = NET_IP_CONFIG_TYPE_STATIC;
		profile_info->ProfileInfo.Wlan.net_info.IpAddr.Data.Ipv4.s_addr = 0;
		profile_info->ProfileInfo.Wlan.net_info.SubnetMask.Data.Ipv4.s_addr = 0;
		profile_info->ProfileInfo.Wlan.net_info.GatewayAddr.Data.Ipv4.s_addr = 0;
		break;
	case WIFI_IP_CONFIG_TYPE_DYNAMIC:
		profile_info->ProfileInfo.Wlan.net_info.IpConfigType = NET_IP_CONFIG_TYPE_DYNAMIC;
		break;
	case WIFI_IP_CONFIG_TYPE_AUTO:
		profile_info->ProfileInfo.Wlan.net_info.IpConfigType = NET_IP_CONFIG_TYPE_AUTO_IP;
		break;
	case WIFI_IP_CONFIG_TYPE_FIXED:
		profile_info->ProfileInfo.Wlan.net_info.IpConfigType = NET_IP_CONFIG_TYPE_FIXED;
		break;
	case WIFI_IP_CONFIG_TYPE_NONE:
		profile_info->ProfileInfo.Wlan.net_info.IpConfigType = NET_IP_CONFIG_TYPE_OFF;
		break;
	default:
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}

int wifi_ap_get_ip_address(wifi_ap_h ap, wifi_address_family_e address_family, char** ip_address)
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

	net_profile_info_t *profile_info = ap;
	*ip_address = __ap_convert_ip_to_string(&profile_info->ProfileInfo.Wlan.net_info.IpAddr);
	if (*ip_address == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_ip_address(wifi_ap_h ap, wifi_address_family_e address_family, const char* ip_address)
{
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

	net_profile_info_t *profile_info = ap;

	if (ip_address == NULL)
		profile_info->ProfileInfo.Wlan.net_info.IpAddr.Data.Ipv4.s_addr = 0;
	else if (inet_aton(ip_address, &(profile_info->ProfileInfo.Wlan.net_info.IpAddr.Data.Ipv4)) == 0)
		return WIFI_ERROR_INVALID_PARAMETER;

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}

int wifi_ap_get_subnet_mask(wifi_ap_h ap, wifi_address_family_e address_family, char** subnet_mask)
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

	net_profile_info_t *profile_info = ap;
	*subnet_mask = __ap_convert_ip_to_string(&profile_info->ProfileInfo.Wlan.net_info.SubnetMask);
	if (*subnet_mask == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_subnet_mask(wifi_ap_h ap, wifi_address_family_e address_family, const char* subnet_mask)
{
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

	net_profile_info_t *profile_info = ap;

	if (subnet_mask == NULL)
		profile_info->ProfileInfo.Wlan.net_info.SubnetMask.Data.Ipv4.s_addr = 0;
	else if (inet_aton(subnet_mask, &(profile_info->ProfileInfo.Wlan.net_info.SubnetMask.Data.Ipv4)) == 0)
		return WIFI_ERROR_INVALID_PARAMETER;

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}

int wifi_ap_get_gateway_address(wifi_ap_h ap, wifi_address_family_e address_family, char** gateway_address)
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

	net_profile_info_t *profile_info = ap;
	*gateway_address = __ap_convert_ip_to_string(&profile_info->ProfileInfo.Wlan.net_info.GatewayAddr);
	if (*gateway_address == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_gateway_address(wifi_ap_h ap, wifi_address_family_e address_family, const char* gateway_address)
{
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

	net_profile_info_t *profile_info = ap;

	if (gateway_address == NULL)
		profile_info->ProfileInfo.Wlan.net_info.GatewayAddr.Data.Ipv4.s_addr = 0;
	else if (inet_aton(gateway_address, &(profile_info->ProfileInfo.Wlan.net_info.GatewayAddr.Data.Ipv4)) == 0)
		return WIFI_ERROR_INVALID_PARAMETER;

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}

int wifi_ap_get_proxy_address(wifi_ap_h ap, wifi_address_family_e address_family, char** proxy_address)
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

	net_profile_info_t *profile_info = ap;
	*proxy_address = g_strdup(profile_info->ProfileInfo.Wlan.net_info.ProxyAddr);
	if (*proxy_address == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_proxy_address(wifi_ap_h ap, wifi_address_family_e address_family, const char* proxy_address)
{
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

	net_profile_info_t *profile_info = ap;

	if (proxy_address == NULL)
		profile_info->ProfileInfo.Wlan.net_info.ProxyAddr[0] = '\0';
	else
		g_strlcpy(profile_info->ProfileInfo.Wlan.net_info.ProxyAddr,
				proxy_address, NET_PROXY_LEN_MAX+1);

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}

int wifi_ap_get_proxy_type(wifi_ap_h ap, wifi_proxy_type_e* type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (profile_info->ProfileInfo.Wlan.net_info.ProxyMethod) {
	case NET_PROXY_TYPE_DIRECT:
		*type = WIFI_PROXY_TYPE_DIRECT;
		break;
	case NET_PROXY_TYPE_AUTO:
		*type = WIFI_PROXY_TYPE_AUTO;
		break;
	case NET_PROXY_TYPE_MANUAL:
		*type = WIFI_PROXY_TYPE_MANUAL;
		break;
	case NET_PROXY_TYPE_UNKNOWN:
		*type = WIFI_PROXY_TYPE_DIRECT;
		break;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_proxy_type(wifi_ap_h ap, wifi_proxy_type_e proxy_type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	int rv;

	switch (proxy_type) {
	case WIFI_PROXY_TYPE_DIRECT:
		profile_info->ProfileInfo.Wlan.net_info.ProxyMethod = NET_PROXY_TYPE_DIRECT;
		break;
	case WIFI_PROXY_TYPE_AUTO:
		profile_info->ProfileInfo.Wlan.net_info.ProxyAddr[0] = '\0';
		profile_info->ProfileInfo.Wlan.net_info.ProxyMethod = NET_PROXY_TYPE_AUTO;
		break;
	case WIFI_PROXY_TYPE_MANUAL:
		profile_info->ProfileInfo.Wlan.net_info.ProxyAddr[0] = '\0';
		profile_info->ProfileInfo.Wlan.net_info.ProxyMethod = NET_PROXY_TYPE_MANUAL;
		break;
	default:
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	rv =_wifi_update_ap_info(profile_info);
	if (rv != NET_ERR_NONE && proxy_type == WIFI_PROXY_TYPE_MANUAL) {
		g_strlcpy(profile_info->ProfileInfo.Wlan.net_info.ProxyAddr, "0.0.0.0:8080", 15);
		rv = _wifi_update_ap_info(profile_info);
	}

	return rv;
}

int wifi_ap_get_dns_address(wifi_ap_h ap, int order, wifi_address_family_e address_family, char** dns_address)
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

	net_profile_info_t *profile_info = ap;

	*dns_address = __ap_convert_ip_to_string(&profile_info->ProfileInfo.Wlan.net_info.DnsAddr[order-1]);
	if (*dns_address == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_dns_address(wifi_ap_h ap, int order, wifi_address_family_e address_family, const char* dns_address)
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

	net_profile_info_t *profile_info = ap;

	if (dns_address == NULL)
		profile_info->ProfileInfo.Wlan.net_info.DnsAddr[order-1].Data.Ipv4.s_addr = 0;
	else if (inet_aton(dns_address, &(profile_info->ProfileInfo.Wlan.net_info.DnsAddr[order-1].Data.Ipv4)) == 0)
		return WIFI_ERROR_INVALID_PARAMETER;

	if (profile_info->ProfileInfo.Wlan.net_info.DnsCount < order)
		profile_info->ProfileInfo.Wlan.net_info.DnsCount = order;

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}



/* Wi-Fi security information module **************************************************************/

int wifi_ap_get_security_type(wifi_ap_h ap, wifi_security_type_e* type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (profile_info->ProfileInfo.Wlan.security_info.sec_mode) {
	case WLAN_SEC_MODE_NONE:
		*type = WIFI_SECURITY_TYPE_NONE;
		break;
	case WLAN_SEC_MODE_WEP:
		*type = WIFI_SECURITY_TYPE_WEP;
		break;
	case WLAN_SEC_MODE_IEEE8021X:
		*type = WIFI_SECURITY_TYPE_EAP;
		break;
	case WLAN_SEC_MODE_WPA_PSK:
		*type = WIFI_SECURITY_TYPE_WPA_PSK;
		break;
	case WLAN_SEC_MODE_WPA2_PSK:
		*type = WIFI_SECURITY_TYPE_WPA2_PSK;
		break;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_security_type(wifi_ap_h ap, wifi_security_type_e type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (type) {
	case WIFI_SECURITY_TYPE_NONE:
		profile_info->ProfileInfo.Wlan.security_info.sec_mode = WLAN_SEC_MODE_NONE;
		break;
	case WIFI_SECURITY_TYPE_WEP:
		profile_info->ProfileInfo.Wlan.security_info.sec_mode = WLAN_SEC_MODE_WEP;
		break;
	case WIFI_SECURITY_TYPE_EAP:
		profile_info->ProfileInfo.Wlan.security_info.sec_mode = WLAN_SEC_MODE_IEEE8021X;
		break;
	case WIFI_SECURITY_TYPE_WPA_PSK:
		profile_info->ProfileInfo.Wlan.security_info.sec_mode = WLAN_SEC_MODE_WPA_PSK;
		break;
	case WIFI_SECURITY_TYPE_WPA2_PSK:
		profile_info->ProfileInfo.Wlan.security_info.sec_mode = WLAN_SEC_MODE_WPA2_PSK;
		break;
	default:
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_encryption_type(wifi_ap_h ap, wifi_encryption_type_e* type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (profile_info->ProfileInfo.Wlan.security_info.enc_mode) {
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

int wifi_ap_set_encryption_type(wifi_ap_h ap, wifi_encryption_type_e type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (type) {
	case WIFI_ENCRYPTION_TYPE_NONE:
		profile_info->ProfileInfo.Wlan.security_info.enc_mode = WLAN_ENC_MODE_NONE;
		break;
	case WIFI_ENCRYPTION_TYPE_WEP:
		profile_info->ProfileInfo.Wlan.security_info.enc_mode = WLAN_ENC_MODE_WEP;
		break;
	case WIFI_ENCRYPTION_TYPE_TKIP:
		profile_info->ProfileInfo.Wlan.security_info.enc_mode = WLAN_ENC_MODE_TKIP;
		break;
	case WIFI_ENCRYPTION_TYPE_AES:
		profile_info->ProfileInfo.Wlan.security_info.enc_mode = WLAN_ENC_MODE_AES;
		break;
	case WIFI_ENCRYPTION_TYPE_TKIP_AES_MIXED:
		profile_info->ProfileInfo.Wlan.security_info.enc_mode = WLAN_ENC_MODE_TKIP_AES_MIXED;
		break;
	default:
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

int wifi_ap_is_passphrase_required(wifi_ap_h ap, bool* required)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || required == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (profile_info->Favourite) {
		*required = false;
		return WIFI_ERROR_NONE;
	}

	switch (profile_info->ProfileInfo.Wlan.security_info.sec_mode) {
	case WLAN_SEC_MODE_NONE:
		*required = false;
		break;
	case WLAN_SEC_MODE_WEP:
	case WLAN_SEC_MODE_IEEE8021X:
	case WLAN_SEC_MODE_WPA_PSK:
	case WLAN_SEC_MODE_WPA2_PSK:
		*required = true;
		break;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_passphrase(wifi_ap_h ap, const char* passphrase)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || passphrase == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (profile_info->ProfileInfo.Wlan.security_info.sec_mode) {
	case WLAN_SEC_MODE_WEP:
		g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.wep.wepKey,
				passphrase, NETPM_WLAN_MAX_WEP_KEY_LEN+1);
		break;
	case WLAN_SEC_MODE_WPA_PSK:
	case WLAN_SEC_MODE_WPA2_PSK:
		g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.psk.pskKey,
				passphrase, NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN+1);
		break;
	case WLAN_SEC_MODE_NONE:
	case WLAN_SEC_MODE_IEEE8021X:
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}

int wifi_ap_is_wps_supported(wifi_ap_h ap, bool* supported)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || supported == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (profile_info->ProfileInfo.Wlan.security_info.wps_support)
		*supported = true;
	else
		*supported = false;

	return WIFI_ERROR_NONE;
}



/* Wi-Fi EAP module *******************************************************************************/

int wifi_ap_set_eap_passphrase(wifi_ap_h ap, const char* user_name, const char* password)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || (user_name == NULL && password == NULL)) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	if (user_name)
		g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.username,
				user_name, NETPM_WLAN_USERNAME_LEN+1);

	if (password)
		g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.password,
				password, NETPM_WLAN_PASSWORD_LEN+1);

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_eap_passphrase(wifi_ap_h ap, char** user_name, bool* is_password_set)
{
	if (_wifi_libnet_check_ap_validity(ap) == false ||user_name == NULL || is_password_set == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	*user_name = g_strdup(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.username);
	if (*user_name == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	if (strlen(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.password) > 0)
		*is_password_set = true;
	else
		*is_password_set = false;


	return WIFI_ERROR_NONE;
}

int wifi_ap_get_eap_ca_cert_file(wifi_ap_h ap, char** file)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	*file = g_strdup(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.ca_cert_filename);
	if (*file == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_eap_ca_cert_file(wifi_ap_h ap, const char* file)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.ca_cert_filename,
			file, NETPM_WLAN_CA_CERT_FILENAME_LEN+1);

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_eap_client_cert_file(wifi_ap_h ap, char** file)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	*file = g_strdup(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.client_cert_filename);
	if (*file == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_eap_client_cert_file(wifi_ap_h ap, const char* file)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.client_cert_filename,
			file, NETPM_WLAN_CLIENT_CERT_FILENAME_LEN+1);

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_eap_private_key_file(wifi_ap_h ap, char** file)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	*file = g_strdup(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.private_key_filename);
	if (*file == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_eap_private_key_info(wifi_ap_h ap, const char* file, const char* password)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL || password == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.private_key_filename,
			file, NETPM_WLAN_PRIVATE_KEY_FILENAME_LEN+1);
	g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.private_key_passwd,
			password, NETPM_WLAN_PRIVATE_KEY_PASSWD_LEN+1);

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_eap_type(wifi_ap_h ap, wifi_eap_type_e* type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	switch (profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_type) {
	case WLAN_SEC_EAP_TYPE_PEAP:
		*type = WIFI_EAP_TYPE_PEAP;
		break;
	case WLAN_SEC_EAP_TYPE_TLS:
		*type = WIFI_EAP_TYPE_TLS;
		break;
	case WLAN_SEC_EAP_TYPE_TTLS:
		*type = WIFI_EAP_TYPE_TTLS;
		break;
	case WLAN_SEC_EAP_TYPE_SIM:
		*type = WIFI_EAP_TYPE_SIM;
		break;
	case WLAN_SEC_EAP_TYPE_AKA:
		*type = WIFI_EAP_TYPE_AKA;
		break;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_eap_type(wifi_ap_h ap, wifi_eap_type_e type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	switch (type) {
	case WIFI_EAP_TYPE_PEAP:
		profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_type = WLAN_SEC_EAP_TYPE_PEAP;
		break;
	case WIFI_EAP_TYPE_TLS:
		profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_type = WLAN_SEC_EAP_TYPE_TLS;
		break;
	case WIFI_EAP_TYPE_TTLS:
		profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_type = WLAN_SEC_EAP_TYPE_TTLS;
		break;
	case WIFI_EAP_TYPE_SIM:
		profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_type = WLAN_SEC_EAP_TYPE_SIM;
		break;
	case WIFI_EAP_TYPE_AKA:
		profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_type = WLAN_SEC_EAP_TYPE_AKA;
		break;
	default:
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}

int wifi_ap_get_eap_auth_type(wifi_ap_h ap, wifi_eap_auth_type_e* type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	switch (profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_auth) {
	case WLAN_SEC_EAP_AUTH_NONE:
		*type = WIFI_EAP_AUTH_TYPE_NONE;
		break;
	case WLAN_SEC_EAP_AUTH_PAP:
		*type = WIFI_EAP_AUTH_TYPE_PAP;
		break;
	case WLAN_SEC_EAP_AUTH_MSCHAP:
		*type = WIFI_EAP_AUTH_TYPE_MSCHAP;
		break;
	case WLAN_SEC_EAP_AUTH_MSCHAPV2:
		*type = WIFI_EAP_AUTH_TYPE_MSCHAPV2;
		break;
	case WLAN_SEC_EAP_AUTH_GTC:
		*type = WIFI_EAP_AUTH_TYPE_GTC;
		break;
	case WLAN_SEC_EAP_AUTH_MD5:
		*type = WIFI_EAP_AUTH_TYPE_MD5;
		break;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	}

	return WIFI_ERROR_NONE;
}

int wifi_ap_set_eap_auth_type(wifi_ap_h ap, wifi_eap_auth_type_e type)
{
	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Wrong Parameter Passed\n");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	switch (type) {
	case WIFI_EAP_AUTH_TYPE_NONE:
		profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_auth = WLAN_SEC_EAP_AUTH_NONE;
		break;
	case WIFI_EAP_AUTH_TYPE_PAP:
		profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_auth = WLAN_SEC_EAP_AUTH_PAP;
		break;
	case WIFI_EAP_AUTH_TYPE_MSCHAP:
		profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_auth = WLAN_SEC_EAP_AUTH_MSCHAP;
		break;
	case WIFI_EAP_AUTH_TYPE_MSCHAPV2:
		profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_auth = WLAN_SEC_EAP_AUTH_MSCHAPV2;
		break;
	case WIFI_EAP_AUTH_TYPE_GTC:
		profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_auth = WLAN_SEC_EAP_AUTH_GTC;
		break;
	case WIFI_EAP_AUTH_TYPE_MD5:
		profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_auth = WLAN_SEC_EAP_AUTH_MD5;
		break;
	default:
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	return WIFI_ERROR_NONE;
}


