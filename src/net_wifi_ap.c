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
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "net_wifi_private.h"

#define MAX_PREFIX_LENGTH 6

static char *__ap_convert_ip_to_string(net_addr_t *ip_addr, wifi_address_family_e address_family)
{
	unsigned char *ipaddr = NULL;
	char *ipstr = NULL;

	if (address_family == WIFI_ADDRESS_FAMILY_IPV4) {
		ipaddr = (unsigned char *)&ip_addr->Data.Ipv4.s_addr;
		ipstr = g_try_malloc0(INET_ADDRSTRLEN);
		if (ipstr == NULL)
			return NULL;

		inet_ntop(AF_INET, ipaddr, ipstr, INET_ADDRSTRLEN);
	} else {
		//LCOV_EXCL_START
		ipaddr = (unsigned char *)&ip_addr->Data.Ipv6;
		ipstr = g_try_malloc0(INET6_ADDRSTRLEN);
		if (ipstr == NULL)
			return NULL;

		inet_ntop(AF_INET6, ipaddr, ipstr, INET6_ADDRSTRLEN);
		//LCOV_EXCL_STOP
	}
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

static char *__wifi_create_profile_name(const char *ssid, const int net_mode, const int sec_mode)
{
	char *buf = NULL;
	char *pbuf = NULL;
	const char *hidden_str = "hidden";
	char buf_tmp[32] = { 0, };
	int i;
	int ssid_len = 0;
	int actual_len = 0;
	const char *mode = "managed";
	char *g_sec = NULL;

	if (net_mode == NETPM_WLAN_CONNMODE_ADHOC) {
		WIFI_LOG(WIFI_ERROR, "wlan_mode is adhoc"); //LCOV_EXCL_LINE
		return NULL; //LCOV_EXCL_LINE
	}

	switch (sec_mode) {
	//LCOV_EXCL_START
	case WLAN_SEC_MODE_NONE:
		g_sec = "none";
		break;
	case WLAN_SEC_MODE_WEP:
		g_sec = "wep";
		break;
	case WLAN_SEC_MODE_WPA_PSK:
	case WLAN_SEC_MODE_WPA2_PSK:
		g_sec = "psk";
		break;
	case WLAN_SEC_MODE_IEEE8021X:
		g_sec = "ieee8021x";
		break;
	default:
		WIFI_LOG(WIFI_ERROR, "Invalid security type");
		return NULL;
	//LCOV_EXCL_STOP
	}

	if (NULL != ssid) {
		ssid_len = strlen(ssid);
		actual_len = ssid_len * 2;
	} else {
		ssid_len = strlen(hidden_str);
		actual_len = ssid_len;
	}

	buf = g_try_malloc0(actual_len + strlen(mode) + strlen(g_sec) + 3);
	if (buf == NULL)
		return NULL;

	if (NULL != ssid) {
		pbuf = buf;

		for (i = 0; i < ssid_len; i++) {
			g_snprintf(pbuf, 3, "%02x", ssid[i]);
			pbuf += 2;
		}
	} else
		g_strlcat(buf, hidden_str,
				actual_len + strlen(mode) + strlen(g_sec) + 3);

	g_snprintf(buf_tmp, 32, "_%s_%s", mode, g_sec);
	g_strlcat(buf, buf_tmp,
			actual_len + strlen(mode) + strlen(g_sec) + 3);

	WIFI_LOG(WIFI_INFO, "Profile name: %s", buf);

	return buf;
}

static bool _wifi_set_profile_name_to_ap(net_profile_info_t *ap_info)
{
	char *profile_name = NULL;

	if (ap_info == NULL) {
		WIFI_LOG(WIFI_ERROR, "profile_info is NULL"); //LCOV_EXCL_LINE
		return false; //LCOV_EXCL_LINE
	}

	profile_name = __wifi_create_profile_name(
			ap_info->ProfileInfo.Wlan.is_hidden == TRUE ?
					NULL : ap_info->ProfileInfo.Wlan.essid,
			ap_info->ProfileInfo.Wlan.wlan_mode,
			ap_info->ProfileInfo.Wlan.security_info.sec_mode);
	if (profile_name == NULL) {
		WIFI_LOG(WIFI_ERROR, "Failed to make a group name"); //LCOV_EXCL_LINE
		return false; //LCOV_EXCL_LINE
	}

	g_strlcpy(ap_info->ProfileInfo.Wlan.net_info.ProfileName,
			profile_name, NET_PROFILE_NAME_LEN_MAX);

	g_free(profile_name);

	return true;
}

wifi_connection_state_e _wifi_convert_to_ap_state(net_state_type_t state)
{
	wifi_connection_state_e ap_state;

	switch (state) {
	case NET_STATE_TYPE_ONLINE:
	case NET_STATE_TYPE_READY:
		ap_state = WIFI_CONNECTION_STATE_CONNECTED;
		break;
	case NET_STATE_TYPE_FAILURE:
		ap_state = WIFI_CONNECTION_STATE_FAILURE;
		break;
	case NET_STATE_TYPE_IDLE:
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
EXPORT_API int wifi_ap_create(const char* essid, wifi_ap_h* ap)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (essid == NULL || ap == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
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

EXPORT_API int wifi_ap_hidden_create(const char* essid, wifi_ap_h* ap)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (essid == NULL || ap == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *ap_info = g_try_malloc0(sizeof(net_profile_info_t));
	if (ap_info == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY; //LCOV_EXCL_LINE

	__wifi_init_ap(ap_info, essid);
	ap_info->ProfileInfo.Wlan.is_hidden = TRUE;

	_wifi_libnet_add_to_ap_list((wifi_ap_h)ap_info);
	*ap = (wifi_ap_h)ap_info;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_destroy(wifi_ap_h ap)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	_wifi_libnet_remove_from_ap_list(ap);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_clone(wifi_ap_h* cloned_ap, wifi_ap_h origin)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(origin) == false || cloned_ap == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *ap_info = g_try_malloc0(sizeof(net_profile_info_t));
	if (ap_info == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY; //LCOV_EXCL_LINE

	memcpy(ap_info, origin, sizeof(net_profile_info_t));

	_wifi_libnet_add_to_ap_list((wifi_ap_h)ap_info);
	*cloned_ap = (wifi_ap_h)ap_info;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_refresh(wifi_ap_h ap)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	net_profile_info_t ap_info_local;
	net_profile_info_t *ap_info = ap;

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	int rv = NET_ERR_NONE;
	rv = net_get_profile_info(ap_info->ProfileName, &ap_info_local);
	if (rv == NET_ERR_ACCESS_DENIED) {
		WIFI_LOG(WIFI_ERROR, "Access denied"); //LCOV_EXCL_LINE
		return WIFI_ERROR_PERMISSION_DENIED; //LCOV_EXCL_LINE
	} else if (rv != NET_ERR_NONE) {
		WIFI_LOG(WIFI_ERROR, "Failed to getprofile_info"); //LCOV_EXCL_LINE
		return WIFI_ERROR_OPERATION_FAILED; //LCOV_EXCL_LINE
	}

	memcpy(ap, &ap_info_local, sizeof(net_profile_info_t));

	return WIFI_ERROR_NONE;
}

/* Wi-Fi network information *************************************************/
EXPORT_API int wifi_ap_get_essid(wifi_ap_h ap, char** essid)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || essid == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	*essid = g_strdup(profile_info->ProfileInfo.Wlan.essid);
	if (*essid == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY; //LCOV_EXCL_LINE

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_bssid(wifi_ap_h ap, char** bssid)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || bssid == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	*bssid = g_strdup(profile_info->ProfileInfo.Wlan.bssid);
	if (*bssid == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY; //LCOV_EXCL_LINE

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_rssi(wifi_ap_h ap, int* rssi)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || rssi == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	*rssi = (int)(profile_info->ProfileInfo.Wlan.Strength - 120);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_frequency(wifi_ap_h ap, int* frequency)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || frequency == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	*frequency = (int)profile_info->ProfileInfo.Wlan.frequency;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_max_speed(wifi_ap_h ap, int* max_speed)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || max_speed == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	*max_speed = (int)profile_info->ProfileInfo.Wlan.max_rate / 1000000;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_is_favorite(wifi_ap_h ap, bool* favorite)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || favorite == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (profile_info->Favourite)
		*favorite = true;
	else
		*favorite = false;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_is_passpoint(wifi_ap_h ap, bool* passpoint)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || passpoint == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (profile_info->ProfileInfo.Wlan.passpoint)
		*passpoint = true;
	else
		*passpoint = false;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_connection_state(wifi_ap_h ap, wifi_connection_state_e* state)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || state == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	*state = _wifi_convert_to_ap_state(profile_info->ProfileState);

	if (*state < 0)
		return WIFI_ERROR_OPERATION_FAILED; //LCOV_EXCL_LINE

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_ip_config_type(wifi_ap_h ap, wifi_address_family_e address_family, wifi_ip_config_type_e* type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);
	net_ip_config_type_t profileType ;

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (address_family == WIFI_ADDRESS_FAMILY_IPV4)
		profileType = profile_info->ProfileInfo.Wlan.net_info.IpConfigType ;
	else
		profileType = profile_info->ProfileInfo.Wlan.net_info.IpConfigType6 ; //LCOV_EXCL_LINE

	if (address_family == WIFI_ADDRESS_FAMILY_IPV4) {
		switch (profileType) {
		//LCOV_EXCL_START
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
		//LCOV_EXCL_STOP
		}
	} else {
		//LCOV_EXCL_START
		switch (profileType) {
		case NET_IP_CONFIG_TYPE_STATIC:
			*type = WIFI_IP_CONFIG_TYPE_STATIC;
			break;
		case NET_IP_CONFIG_TYPE_AUTO_IP:
			*type = WIFI_IP_CONFIG_TYPE_AUTO;
			break;
		case NET_IP_CONFIG_TYPE_OFF:
			*type = WIFI_IP_CONFIG_TYPE_NONE;
			break;
		default:
			return WIFI_ERROR_OPERATION_FAILED;
		}
		//LCOV_EXCL_STOP
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_ip_config_type(wifi_ap_h ap, wifi_address_family_e address_family, wifi_ip_config_type_e type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);
	net_ip_config_type_t *profileType = NULL;

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (address_family == WIFI_ADDRESS_FAMILY_IPV4)
		profileType = &profile_info->ProfileInfo.Wlan.net_info.IpConfigType ;
	else
		profileType = &profile_info->ProfileInfo.Wlan.net_info.IpConfigType6 ;

	if (address_family == WIFI_ADDRESS_FAMILY_IPV4) {
		switch (type) {
		//LCOV_EXCL_START
		case WIFI_IP_CONFIG_TYPE_STATIC:
			*profileType = NET_IP_CONFIG_TYPE_STATIC;
			profile_info->ProfileInfo.Wlan.net_info.IpAddr.Data.Ipv4.s_addr = 0;
			profile_info->ProfileInfo.Wlan.net_info.SubnetMask.Data.Ipv4.s_addr = 0;
			profile_info->ProfileInfo.Wlan.net_info.GatewayAddr.Data.Ipv4.s_addr = 0 ;
			break;

		case WIFI_IP_CONFIG_TYPE_DYNAMIC:
			*profileType = NET_IP_CONFIG_TYPE_DYNAMIC;
			break;

		case WIFI_IP_CONFIG_TYPE_AUTO:
			*profileType = NET_IP_CONFIG_TYPE_AUTO_IP;
			break;

		case WIFI_IP_CONFIG_TYPE_FIXED:
			*profileType = NET_IP_CONFIG_TYPE_FIXED;
			break;

		case WIFI_IP_CONFIG_TYPE_NONE:
			*profileType = NET_IP_CONFIG_TYPE_OFF;
			break;

		default:
			return WIFI_ERROR_INVALID_PARAMETER;
		//LCOV_EXCL_STOP
		}
	} else {
	//LCOV_EXCL_START
		switch (type) {
		case WIFI_IP_CONFIG_TYPE_STATIC:
			*profileType = NET_IP_CONFIG_TYPE_STATIC;
			inet_pton(AF_INET6, "::", &profile_info->ProfileInfo.Wlan.net_info.IpAddr6.Data.Ipv6);
			profile_info->ProfileInfo.Wlan.net_info.PrefixLen6 = 0 ;
			inet_pton(AF_INET6, "::", &profile_info->ProfileInfo.Wlan.net_info.GatewayAddr6.Data.Ipv6);
			break;
		case WIFI_IP_CONFIG_TYPE_AUTO:
			*profileType = NET_IP_CONFIG_TYPE_AUTO_IP;
			break;
		case WIFI_IP_CONFIG_TYPE_NONE:
			*profileType = NET_IP_CONFIG_TYPE_OFF;
			break;
		default:
			return WIFI_ERROR_INVALID_PARAMETER;
		}
	//LCOV_EXCL_STOP
	}

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}

EXPORT_API int wifi_ap_get_ip_address(wifi_ap_h ap, wifi_address_family_e address_family, char** ip_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    ip_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (address_family == WIFI_ADDRESS_FAMILY_IPV4)
		*ip_address = __ap_convert_ip_to_string(
				&profile_info->ProfileInfo.Wlan.net_info.IpAddr,
				address_family);
	else
		*ip_address = __ap_convert_ip_to_string(
				&profile_info->ProfileInfo.Wlan.net_info.IpAddr6,
				address_family);

	if (*ip_address == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_ip_address(wifi_ap_h ap, wifi_address_family_e address_family, const char* ip_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (address_family == WIFI_ADDRESS_FAMILY_IPV4) {
		if (ip_address == NULL)
			profile_info->ProfileInfo.Wlan.net_info.IpAddr.Data.Ipv4.s_addr = 0;
		else if (inet_aton(ip_address,
				&(profile_info->ProfileInfo.Wlan.net_info.IpAddr.Data.Ipv4)) == 0)
			return WIFI_ERROR_INVALID_PARAMETER;
	} else {
	//LCOV_EXCL_START
		if (ip_address == NULL)
			inet_pton(AF_INET6, "::",
				&profile_info->ProfileInfo.Wlan.net_info.IpAddr6.Data.Ipv6);
		else if (inet_pton(AF_INET6, ip_address,
				&profile_info->ProfileInfo.Wlan.net_info.IpAddr6.Data.Ipv6) == 0)
			return WIFI_ERROR_INVALID_PARAMETER;
	//LCOV_EXCL_STOP
	}

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}

EXPORT_API int wifi_ap_get_subnet_mask(wifi_ap_h ap, wifi_address_family_e address_family, char** subnet_mask)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);
	char* prefixlen;

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    subnet_mask == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (address_family == WIFI_ADDRESS_FAMILY_IPV4)
		*subnet_mask = __ap_convert_ip_to_string(
			&profile_info->ProfileInfo.Wlan.net_info.SubnetMask,
			address_family);
	else {
		//LCOV_EXCL_START
		prefixlen = g_try_malloc0(MAX_PREFIX_LENGTH);
		if (prefixlen != NULL) {
			snprintf(prefixlen, MAX_PREFIX_LENGTH, "%d",
				profile_info->ProfileInfo.Wlan.net_info.PrefixLen6);
			*subnet_mask = prefixlen;
		} else
			*subnet_mask = NULL;
		//LCOV_EXCL_STOP
	}

	if (*subnet_mask == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_subnet_mask(wifi_ap_h ap, wifi_address_family_e address_family, const char* subnet_mask)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	/* Based on the family of address provided subnet mask should be set.
	 * For IPv6 address subnet mask is prefix length, an integer,  while for
	 * Ipv6 address subnet mask is a ipv6 address.
	 */
	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		//LCOV_EXCL_START
		if (subnet_mask == NULL)
			profile_info->ProfileInfo.Wlan.net_info.PrefixLen6 = 0;
		else {
			/* subnet mask provided as input parameter is a string
			 * while for IPv6 address subnet mask in prefix length
			 * which should be in integer form */
			profile_info->ProfileInfo.Wlan.net_info.PrefixLen6 =
				atoi(subnet_mask) ;
		}
		//LCOV_EXCL_STOP
	} else {
		if (subnet_mask == NULL)
			profile_info->ProfileInfo.Wlan.net_info.SubnetMask.Data.Ipv4.s_addr = 0;
		else if (inet_pton(AF_INET, subnet_mask,
				&(profile_info->ProfileInfo.Wlan.net_info.SubnetMask.Data.Ipv4)) < 1)
			return WIFI_ERROR_INVALID_PARAMETER;
	}


	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}

EXPORT_API int wifi_ap_get_gateway_address(wifi_ap_h ap, wifi_address_family_e address_family, char** gateway_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    gateway_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	/* Based on the family of address provided, gateway should be set.
	 * For IPv6 address gateway is of form GatewayAddr6 but for IPv4
	 * gateway is of form GatewayAddr.
	 */
	if (address_family == WIFI_ADDRESS_FAMILY_IPV4)
		*gateway_address = __ap_convert_ip_to_string(
			&profile_info->ProfileInfo.Wlan.net_info.GatewayAddr,
			address_family);
	else
		*gateway_address = __ap_convert_ip_to_string( //LCOV_EXCL_LINE
			&profile_info->ProfileInfo.Wlan.net_info.GatewayAddr6,
			address_family);

	if (*gateway_address == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_gateway_address(wifi_ap_h ap, wifi_address_family_e address_family, const char* gateway_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		//LCOV_EXCL_START
		if (gateway_address == NULL)
			inet_pton(AF_INET6, "::",
				&profile_info->ProfileInfo.Wlan.net_info.GatewayAddr6.Data.Ipv6);
		else if (inet_pton(AF_INET6, gateway_address,
				&profile_info->ProfileInfo.Wlan.net_info.GatewayAddr6.Data.Ipv6) < 1)
			return WIFI_ERROR_INVALID_PARAMETER;
		//LCOV_EXCL_STOP
	} else {
		if (gateway_address == NULL)
			profile_info->ProfileInfo.Wlan.net_info.GatewayAddr.Data.Ipv4.s_addr = 0;
		else if (inet_pton(AF_INET, gateway_address,
				&profile_info->ProfileInfo.Wlan.net_info.GatewayAddr.Data.Ipv4) < 1)
			return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}

EXPORT_API int wifi_ap_get_proxy_address(wifi_ap_h ap, wifi_address_family_e address_family, char** proxy_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    proxy_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	*proxy_address = g_strdup(profile_info->ProfileInfo.Wlan.net_info.ProxyAddr);
	if (*proxy_address == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_proxy_address(wifi_ap_h ap, wifi_address_family_e address_family, const char* proxy_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
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

EXPORT_API int wifi_ap_get_proxy_type(wifi_ap_h ap, wifi_proxy_type_e* type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (profile_info->ProfileInfo.Wlan.net_info.ProxyMethod) {
	//LCOV_EXCL_START
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
	//LCOV_EXCL_STOP
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_proxy_type(wifi_ap_h ap, wifi_proxy_type_e proxy_type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	int rv;

	switch (proxy_type) {
	//LCOV_EXCL_START
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
	//LCOV_EXCL_STOP
	}

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	rv = _wifi_update_ap_info(profile_info);
	if (rv != NET_ERR_NONE && proxy_type == WIFI_PROXY_TYPE_MANUAL) {
		g_strlcpy(profile_info->ProfileInfo.Wlan.net_info.ProxyAddr, "0.0.0.0:8080", 15);
		rv = _wifi_update_ap_info(profile_info);
	}

	return rv;
}

EXPORT_API int wifi_ap_get_dns_address(wifi_ap_h ap, int order, wifi_address_family_e address_family, char** dns_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    dns_address == NULL ||
	    order <= 0 ||
	    order > NET_DNS_ADDR_MAX) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (address_family == WIFI_ADDRESS_FAMILY_IPV4)
		*dns_address = __ap_convert_ip_to_string(
				&profile_info->ProfileInfo.Wlan.net_info.DnsAddr[order-1],
				address_family);
	else
		*dns_address = __ap_convert_ip_to_string( //LCOV_EXCL_LINE
				&profile_info->ProfileInfo.Wlan.net_info.DnsAddr6[order-1],
				address_family);

	if (*dns_address == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_dns_address(wifi_ap_h ap, int order, wifi_address_family_e address_family, const char* dns_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false ||
	    (address_family != WIFI_ADDRESS_FAMILY_IPV4 &&
	     address_family != WIFI_ADDRESS_FAMILY_IPV6) ||
	    order <= 0 ||
	    order > NET_DNS_ADDR_MAX) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		//LCOV_EXCL_START
		profile_info->ProfileInfo.Wlan.net_info.DnsAddr6[order-1].Type =
			NET_ADDR_IPV6;
		if (dns_address == NULL)
			inet_pton(AF_INET6, "::",
					&profile_info->ProfileInfo.Wlan.net_info.DnsAddr6[order-1].Data.Ipv6);
		else if (inet_pton(AF_INET6, dns_address,
					&profile_info->ProfileInfo.Wlan.net_info.DnsAddr6[order-1].Data.Ipv6) < 1)
			return WIFI_ERROR_INVALID_PARAMETER;

		if (profile_info->ProfileInfo.Wlan.net_info.DnsCount6 < order)
			profile_info->ProfileInfo.Wlan.net_info.DnsCount6 = order;
		//LCOV_EXCL_STOP
	} else {
		profile_info->ProfileInfo.Wlan.net_info.DnsAddr[order-1].Type =
			NET_ADDR_IPV4;
		if (dns_address == NULL)
			profile_info->ProfileInfo.Wlan.net_info.DnsAddr[order-1].Data.Ipv4.s_addr = 0;
		else if (inet_pton(AF_INET, dns_address,
					&(profile_info->ProfileInfo.Wlan.net_info.DnsAddr[order-1].Data.Ipv4)) < 1)
			return WIFI_ERROR_INVALID_PARAMETER;

		if (profile_info->ProfileInfo.Wlan.net_info.DnsCount < order)
			profile_info->ProfileInfo.Wlan.net_info.DnsCount = order;
	}

	if (_wifi_libnet_check_profile_name_validity(profile_info->ProfileName) == false)
		return WIFI_ERROR_NONE;

	return _wifi_update_ap_info(profile_info);
}

/* Wi-Fi security information ************************************************/
EXPORT_API int wifi_ap_get_security_type(wifi_ap_h ap, wifi_security_type_e* type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (profile_info->ProfileInfo.Wlan.security_info.sec_mode) {
	//LCOV_EXCL_START
	case WLAN_SEC_MODE_NONE:
		*type = WIFI_SECURITY_TYPE_NONE;
		break;
	case WLAN_SEC_MODE_WEP:
		*type = WIFI_SECURITY_TYPE_WEP; //LCOV_EXCL_LINE
		break;
	case WLAN_SEC_MODE_IEEE8021X:
		*type = WIFI_SECURITY_TYPE_EAP; //LCOV_EXCL_LINE
		break;
	case WLAN_SEC_MODE_WPA_PSK:
		*type = WIFI_SECURITY_TYPE_WPA_PSK; //LCOV_EXCL_LINE
		break;
	case WLAN_SEC_MODE_WPA2_PSK:
		*type = WIFI_SECURITY_TYPE_WPA2_PSK; //LCOV_EXCL_LINE
		break;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	//LCOV_EXCL_STOP
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_security_type(wifi_ap_h ap, wifi_security_type_e type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (type) {
	//LCOV_EXCL_START
	case WIFI_SECURITY_TYPE_NONE:
		profile_info->ProfileInfo.Wlan.security_info.sec_mode = WLAN_SEC_MODE_NONE; //LCOV_EXCL_LINE
		break;
	case WIFI_SECURITY_TYPE_WEP:
		profile_info->ProfileInfo.Wlan.security_info.sec_mode = WLAN_SEC_MODE_WEP; //LCOV_EXCL_LINE
		break;
	case WIFI_SECURITY_TYPE_EAP:
		profile_info->ProfileInfo.Wlan.security_info.sec_mode = WLAN_SEC_MODE_IEEE8021X;
		break;
	case WIFI_SECURITY_TYPE_WPA_PSK:
		profile_info->ProfileInfo.Wlan.security_info.sec_mode = WLAN_SEC_MODE_WPA_PSK; //LCOV_EXCL_LINE
		break;
	case WIFI_SECURITY_TYPE_WPA2_PSK:
		profile_info->ProfileInfo.Wlan.security_info.sec_mode = WLAN_SEC_MODE_WPA2_PSK;
		break;
	default:
		return WIFI_ERROR_INVALID_PARAMETER;
	//LCOV_EXCL_STOP
	}

	_wifi_set_profile_name_to_ap(profile_info);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_encryption_type(wifi_ap_h ap, wifi_encryption_type_e* type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (profile_info->ProfileInfo.Wlan.security_info.enc_mode) {
	//LCOV_EXCL_START
	case WLAN_ENC_MODE_NONE:
		*type = WIFI_ENCRYPTION_TYPE_NONE;
		break;
	case WLAN_ENC_MODE_WEP:
		*type = WIFI_ENCRYPTION_TYPE_WEP; //LCOV_EXCL_LINE
		break;
	case WLAN_ENC_MODE_TKIP:
		*type = WIFI_ENCRYPTION_TYPE_TKIP; //LCOV_EXCL_LINE
		break;
	case WLAN_ENC_MODE_AES:
		*type = WIFI_ENCRYPTION_TYPE_AES; //LCOV_EXCL_LINE
		break;
	case WLAN_ENC_MODE_TKIP_AES_MIXED:
		*type = WIFI_ENCRYPTION_TYPE_TKIP_AES_MIXED; //LCOV_EXCL_LINE
		break;
	default:
		return WIFI_ERROR_OPERATION_FAILED;
	//LCOV_EXCL_STOP
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_encryption_type(wifi_ap_h ap, wifi_encryption_type_e type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (type) {
	//LCOV_EXCL_START
	case WIFI_ENCRYPTION_TYPE_NONE:
		profile_info->ProfileInfo.Wlan.security_info.enc_mode = WLAN_ENC_MODE_NONE; //LCOV_EXCL_LINE
		break;
	case WIFI_ENCRYPTION_TYPE_WEP:
		profile_info->ProfileInfo.Wlan.security_info.enc_mode = WLAN_ENC_MODE_WEP; //LCOV_EXCL_LINE
		break;
	case WIFI_ENCRYPTION_TYPE_TKIP:
		profile_info->ProfileInfo.Wlan.security_info.enc_mode = WLAN_ENC_MODE_TKIP; //LCOV_EXCL_LINE
		break;
	case WIFI_ENCRYPTION_TYPE_AES:
		profile_info->ProfileInfo.Wlan.security_info.enc_mode = WLAN_ENC_MODE_AES;
		break;
	case WIFI_ENCRYPTION_TYPE_TKIP_AES_MIXED:
		profile_info->ProfileInfo.Wlan.security_info.enc_mode = WLAN_ENC_MODE_TKIP_AES_MIXED; //LCOV_EXCL_LINE
		break;
	default:
		return WIFI_ERROR_INVALID_PARAMETER;
	//LCOV_EXCL_STOP
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_is_passphrase_required(wifi_ap_h ap, bool* required)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || required == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (profile_info->Favourite) {
		*required = false;
		return WIFI_ERROR_NONE;
	}

	switch (profile_info->ProfileInfo.Wlan.security_info.sec_mode) {
	//LCOV_EXCL_START
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
	//LCOV_EXCL_STOP
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_passphrase(wifi_ap_h ap, const char* passphrase)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || passphrase == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	switch (profile_info->ProfileInfo.Wlan.security_info.sec_mode) {
	//LCOV_EXCL_START
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
	//LCOV_EXCL_STOP
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_is_wps_supported(wifi_ap_h ap, bool* supported)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || supported == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;

	if (profile_info->ProfileInfo.Wlan.security_info.wps_support)
		*supported = true;
	else
		*supported = false;

	return WIFI_ERROR_NONE;
}

/* Wi-Fi EAP *****************************************************************/
EXPORT_API int wifi_ap_set_eap_passphrase(wifi_ap_h ap, const char* user_name, const char* password)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || (user_name == NULL && password == NULL)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
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

EXPORT_API int wifi_ap_get_eap_passphrase(wifi_ap_h ap, char** user_name, bool* is_password_set)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || user_name == NULL || is_password_set == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
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

EXPORT_API int wifi_ap_get_eap_ca_cert_file(wifi_ap_h ap, char** file)
{
	net_profile_info_t *profile_info = NULL;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	profile_info = (net_profile_info_t *)ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	*file = g_strdup(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.ca_cert_filename);
	if (*file == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_eap_ca_cert_file(wifi_ap_h ap, const char* file)
{
	net_profile_info_t *profile_info = NULL;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	profile_info = (net_profile_info_t *)ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.ca_cert_filename,
			file, NETPM_WLAN_CA_CERT_FILENAME_LEN+1);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_eap_client_cert_file(wifi_ap_h ap, char** file)
{
	net_profile_info_t *profile_info = NULL;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	profile_info = (net_profile_info_t *)ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	*file = g_strdup(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.client_cert_filename);
	if (*file == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_eap_client_cert_file(wifi_ap_h ap, const char* file)
{
	net_profile_info_t *profile_info = NULL;

	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	profile_info = (net_profile_info_t *)ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.client_cert_filename,
			file, NETPM_WLAN_CLIENT_CERT_FILENAME_LEN+1);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_eap_private_key_file(wifi_ap_h ap, char** file)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
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

EXPORT_API int wifi_ap_set_eap_private_key_info(wifi_ap_h ap, const char* file, const char* password)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || file == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.private_key_filename,
			file, NETPM_WLAN_PRIVATE_KEY_FILENAME_LEN+1);

	if (password) {
		g_strlcpy(profile_info->ProfileInfo.Wlan.security_info.authentication.eap.private_key_passwd,
				password, NETPM_WLAN_PRIVATE_KEY_PASSWD_LEN+1);
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_eap_type(wifi_ap_h ap, wifi_eap_type_e* type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	switch (profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_type) {
	//LCOV_EXCL_START
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
	//LCOV_EXCL_STOP
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_eap_type(wifi_ap_h ap, wifi_eap_type_e type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	switch (type) {
	//LCOV_EXCL_START
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
	//LCOV_EXCL_STOP
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_get_eap_auth_type(wifi_ap_h ap, wifi_eap_auth_type_e* type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false || type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	switch (profile_info->ProfileInfo.Wlan.security_info.authentication.eap.eap_auth) {
	//LCOV_EXCL_START
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
	//LCOV_EXCL_STOP
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_ap_set_eap_auth_type(wifi_ap_h ap, wifi_eap_auth_type_e type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	if (_wifi_libnet_check_ap_validity(ap) == false) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	net_profile_info_t *profile_info = ap;
	if (profile_info->ProfileInfo.Wlan.security_info.sec_mode != WLAN_SEC_MODE_IEEE8021X)
		return WIFI_ERROR_INVALID_OPERATION;

	switch (type) {
	//LCOV_EXCL_START
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
	//LCOV_EXCL_STOP
	}

	return WIFI_ERROR_NONE;
}
