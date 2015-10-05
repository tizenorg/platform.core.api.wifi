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
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <assert.h>
#include <wifi.h>
#include <tizen_error.h>


gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data);

static const char *__test_convert_error_to_string(wifi_error_e err_type)
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
		return "NOT_SUPPORTED";
	}

	return "UNKNOWN";
}

static void __test_device_state_callback(wifi_device_state_e state, void* user_data)
{
	printf("Device state changed callback");

	if (state == WIFI_DEVICE_STATE_ACTIVATED)
		printf(", state : Activated\n");
	else
		printf(", state : Deactivated\n");
}

static void __test_bg_scan_completed_callback(wifi_error_e error_code, void* user_data)
{
	printf("Background Scan Completed, error code : %s\n",
			__test_convert_error_to_string(error_code));
}

static void __test_scan_request_callback(wifi_error_e error_code, void* user_data)
{
	if(user_data != NULL)
		printf("user_data : %s\n", (char *)user_data);

	printf("Scan Completed from scan request, error code : %s\n",
			__test_convert_error_to_string(error_code));
}

static void __test_connection_state_callback(wifi_connection_state_e state, wifi_ap_h ap, void* user_data)
{
	int rv = 0;
	char *ap_name = NULL;

	printf("Connection state changed callback");

	switch (state) {
	case WIFI_CONNECTION_STATE_CONNECTED:
		printf(", state : Connected");
		break;
	case WIFI_CONNECTION_STATE_ASSOCIATION:
		printf(", state : Association");
		break;
	case WIFI_CONNECTION_STATE_CONFIGURATION:
		printf(", state : Configuration");
		break;
	case WIFI_CONNECTION_STATE_DISCONNECTED:
		printf(", state : Disconnected");
		break;
	default:
		printf(", state : Unknown");
	}

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE)
		printf(", Fail to get AP name [%s]\n", __test_convert_error_to_string(rv));
	else {
		printf(", AP name : %s\n", ap_name);
		g_free(ap_name);
	}
}

static void __test_activated_callback(wifi_error_e result, void* user_data)
{
	if (result == WIFI_ERROR_NONE)
		printf("Wi-Fi Activation Succeeded\n");
	else
		printf("Wi-Fi Activation Failed! error : %s\n", __test_convert_error_to_string(result));
}

static void __test_deactivated_callback(wifi_error_e result, void* user_data)
{
	if (result == WIFI_ERROR_NONE)
		printf("Wi-Fi Deactivation Succeeded\n");
	else
		printf("Wi-Fi Deactivation Failed! error : %s\n", __test_convert_error_to_string(result));
}

static void __test_connected_callback(wifi_error_e result, void* user_data)
{
	if (result == WIFI_ERROR_NONE)
		printf("Wi-Fi Connection Succeeded\n");
	else
		printf("Wi-Fi Connection Failed! error : %s\n", __test_convert_error_to_string(result));
}

static void __test_disconnected_callback(wifi_error_e result, void* user_data)
{
	if (result == WIFI_ERROR_NONE)
		printf("Wi-Fi Disconnection Succeeded\n");
	else
		printf("Wi-Fi Disconnection Failed! error : %s\n", __test_convert_error_to_string(result));
}

static void __test_rssi_level_callback(wifi_rssi_level_e rssi_level, void* user_data)
{
	printf("RSSI level changed callback, level = %d\n", rssi_level);
}

static const char* __test_print_state(wifi_connection_state_e state)
{
	switch (state) {
	case WIFI_CONNECTION_STATE_FAILURE:
		return "Failure";
	case WIFI_CONNECTION_STATE_DISCONNECTED:
		return "Disconnected";
	case WIFI_CONNECTION_STATE_ASSOCIATION:
		return "Association";
	case WIFI_CONNECTION_STATE_CONNECTED:
		return "Connected";
	case WIFI_CONNECTION_STATE_CONFIGURATION:
		return "Configuration";
	}

	return "Unknown";
}

static bool __test_found_ap_callback(wifi_ap_h ap, void *user_data)
{
	int rv = 0;
	char *ap_name = NULL;
	wifi_connection_state_e state;

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP name [%s]\n", __test_convert_error_to_string(rv));
		return false;
	}

	rv = wifi_ap_get_connection_state(ap, &state);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get State [%s]\n", __test_convert_error_to_string(rv));
		g_free(ap_name);
		return false;
	}

	printf("AP name : %s, state : %s\n", ap_name, __test_print_state(state));
	g_free(ap_name);

	return true;
}

static bool __test_found_connect_ap_callback(wifi_ap_h ap, void *user_data)
{
	int rv = 0;
	char *ap_name = NULL;
	char *ap_name_part = (char*)user_data;

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP name [%s]\n", __test_convert_error_to_string(rv));
		return false;
	}

	if (strstr(ap_name, ap_name_part) != NULL) {
		bool required = false;

		if (wifi_ap_is_passphrase_required(ap, &required) == WIFI_ERROR_NONE)
			printf("Passphrase required : %s\n", required ? "TRUE" : "FALSE");
		else
			printf("Fail to get Passphrase required\n");

		if (required) {
			char passphrase[100];
			printf("Input passphrase for %s : ", ap_name);
			rv = scanf("%99s", passphrase);

			rv = wifi_ap_set_passphrase(ap, passphrase);
			if (rv != WIFI_ERROR_NONE) {
				printf("Fail to set passphrase : %s\n", __test_convert_error_to_string(rv));
				g_free(ap_name);
				return false;
			}
		}

		rv = wifi_connect(ap, __test_connected_callback, NULL);
		if (rv != WIFI_ERROR_NONE)
			printf("Fail to connection request [%s] : %s\n", ap_name, __test_convert_error_to_string(rv));
		else
			printf("Success to connection request [%s]\n", ap_name);

		g_free(ap_name);
		return false;
	}

	g_free(ap_name);
	return true;
}

static bool __test_found_connect_wps_callback(wifi_ap_h ap, void *user_data)
{
	int rv = 0;
	char *ap_name = NULL;
	char *ap_name_part = (char*)user_data;

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP name [%s]\n", __test_convert_error_to_string(rv));
		return false;
	}

	if (strstr(ap_name, ap_name_part) != NULL) {
		int user_sel;
		char pin[32] = {0,};

		printf("%s - Input WPS method (1:PBC, 2:PIN) :\n", ap_name);
		rv = scanf("%9d", &user_sel);

		switch (user_sel) {
		case 1:
			rv = wifi_connect_by_wps_pbc(ap, __test_connected_callback, NULL);
			break;
		case 2:
			printf("Input PIN code :\n");
			rv = scanf("%31s", pin);
			rv = wifi_connect_by_wps_pin(ap, pin, __test_connected_callback, NULL);
			break;
		default:
			printf("Invalid input!\n");
			g_free(ap_name);
			return false;
		}

		if (rv != WIFI_ERROR_NONE)
			printf("Fail to connection request [%s] : %s\n", ap_name, __test_convert_error_to_string(rv));
		else
			printf("Success to connection request [%s]\n", ap_name);

		g_free(ap_name);
		return false;
	}

	g_free(ap_name);
	return true;
}

static bool __test_found_disconnect_ap_callback(wifi_ap_h ap, void *user_data)
{
	int rv = 0;
	char *ap_name = NULL;
	char *ap_name_part = (char*)user_data;

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP name [%s]\n", __test_convert_error_to_string(rv));
		return false;
	}

	if (strstr(ap_name, ap_name_part) != NULL) {
		rv = wifi_disconnect(ap, __test_disconnected_callback, NULL);
		if (rv != WIFI_ERROR_NONE)
			printf("Fail to disconnection reqeust %s : [%s]\n", ap_name, __test_convert_error_to_string(rv));
		else
			printf("Success to disconnection request %s\n", ap_name);

		g_free(ap_name);
		return false;
	}

	g_free(ap_name);
	return true;
}

static bool __test_found_forget_ap_callback(wifi_ap_h ap, void *user_data)
{
	int rv = 0;
	char *ap_name = NULL;
	char *ap_name_part = (char*)user_data;

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP name [%s]\n", __test_convert_error_to_string(rv));
		return false;
	}

	if (strstr(ap_name, ap_name_part) != NULL) {
		rv = wifi_forget_ap(ap);
		if (rv != WIFI_ERROR_NONE)
			printf("Fail to forget [%s] : %s\n", ap_name, __test_convert_error_to_string(rv));
		else
			printf("Success to forget [%s]\n", ap_name);

		g_free(ap_name);
		return false;
	}

	g_free(ap_name);
	return true;
}

static bool __test_found_eap_ap_callback(wifi_ap_h ap, void *user_data)
{
	int rv = 0;
	char *ap_name = NULL;
	char *ap_name_part = (char*)user_data;

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP name [%s]\n", __test_convert_error_to_string(rv));
		return false;
	}

	if (strstr(ap_name, ap_name_part) != NULL) {
		wifi_security_type_e type;

		if (wifi_ap_get_security_type(ap, &type) == WIFI_ERROR_NONE)
			printf("Security type : %d\n", type);
		else
			printf("Fail to get Security type\n");

		if (type != WIFI_SECURITY_TYPE_EAP) {
			g_free(ap_name);
			return false;
		}

		char input_str1[100];
		printf("Input user name for %s : ", ap_name);
		rv = scanf("%99s", input_str1);

		char input_str2[100];
		printf("Input password for %s : ", ap_name);
		rv = scanf("%99s", input_str2);

		rv = wifi_ap_set_eap_passphrase(ap, input_str1, input_str2);
		if (rv != WIFI_ERROR_NONE) {
			printf("Fail to set eap passphrase : %s\n", __test_convert_error_to_string(rv));
			g_free(ap_name);
			return false;
		}

		char *inputed_name = NULL;
		bool is_pass_set;
		rv = wifi_ap_get_eap_passphrase(ap, &inputed_name, &is_pass_set);
		if (rv != WIFI_ERROR_NONE) {
			printf("Fail to get eap passphrase : %s\n", __test_convert_error_to_string(rv));
			g_free(ap_name);
			return false;
		}

		printf("name : %s, is password set : %s\n", inputed_name, is_pass_set ? "TRUE" : "FALSE");

		rv = wifi_connect(ap, __test_connected_callback, NULL);
		if (rv != WIFI_ERROR_NONE)
			printf("Fail to connection request [%s] : %s\n", ap_name, __test_convert_error_to_string(rv));
		else
			printf("Success to connection request [%s]\n", ap_name);

		g_free(ap_name);
		g_free(inputed_name);
		return false;
	}

	g_free(ap_name);
	return true;
}

static bool test_get_user_int(const char *msg, int *num)
{
	if (msg == NULL || num == NULL)
		return false;

	int rv;
	char buf[32] = {0,};
	printf("%s\n", msg);
	rv = read(0, buf, 32);

	if (rv < 0 || *buf == 0 || *buf == '\n' || *buf == '\r')
		return false;

	*num = atoi(buf);
	return true;
}

static bool __test_found_change_ip_method_callback(wifi_ap_h ap, void *user_data)
{
	int rv;
	char *ap_name;
	char *ap_name_part = (char*)user_data;

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP name [%s]\n", __test_convert_error_to_string(rv));
		return false;
	}

	if (strstr(ap_name, ap_name_part) != NULL) {
		wifi_ip_config_type_e type;
		int method;
		int address_type;

		printf("Input new method type (1:dhcp, 2:manual, 3:auto) :\n");
		rv = scanf("%9d", &method);
		if (rv <= 0) {
			g_free(ap_name);
			return false;
		}

	       rv = test_get_user_int("Input Address type to get"
	                       "(0:IPV4, 1:IPV6):", &address_type);

	       if (rv == false || (address_type != 0 && address_type != 1)) {
	               printf("Invalid input!!\n");
	               return false;
	       }

		switch (method) {
		case 1:
			type = WIFI_IP_CONFIG_TYPE_DYNAMIC;
			break;
		case 2:
			type = WIFI_IP_CONFIG_TYPE_STATIC;
			break;
		case 3:
			type = WIFI_IP_CONFIG_TYPE_AUTO;
			break;
		default:
			printf("Invalid input!\n");
			g_free(ap_name);
			return false;
		}

		rv = wifi_ap_set_ip_config_type(ap, address_type, type);
		if (rv != WIFI_ERROR_NONE)
			printf("Fail to set ip method type[%s]\n", __test_convert_error_to_string(rv));

		if (type == WIFI_IP_CONFIG_TYPE_STATIC) {
			char ip_addr[16];

			printf("Input new ip address (x:skip, 0:clear) :\n");
			rv = scanf("%15s", ip_addr);
			if (rv > 0) {
				switch (ip_addr[0]) {
				case 'x':
					rv = WIFI_ERROR_NONE;
					break;
				case '0':
					rv = wifi_ap_set_ip_address(ap, address_type, NULL);
					break;
				default:
					rv = wifi_ap_set_ip_address(ap, address_type, ip_addr);
				}

				if (rv != WIFI_ERROR_NONE)
					printf("Fail to set ip address[%s]\n",
							__test_convert_error_to_string(rv));
			}

			printf("Input new subnet mask (x:skip, 0:clear) :\n");
			rv = scanf("%15s", ip_addr);
			if (rv > 0) {
				switch (ip_addr[0]) {
				case 'x':
					rv = WIFI_ERROR_NONE;
					break;
				case '0':
					rv = wifi_ap_set_subnet_mask(ap, address_type, NULL);
					break;
				default:
					rv = wifi_ap_set_subnet_mask(ap, address_type, ip_addr);
				}

				if (rv != WIFI_ERROR_NONE)
					printf("Fail to set subnet mask[%s]\n",
							__test_convert_error_to_string(rv));
			}

			printf("Input new gateway address (x:skip, 0:clear) :\n");
			rv = scanf("%15s", ip_addr);
			if (rv > 0) {
				switch (ip_addr[0]) {
				case 'x':
					rv = WIFI_ERROR_NONE;
					break;
				case '0':
					rv = wifi_ap_set_gateway_address(ap, address_type, NULL);
					break;
				default:
					rv = wifi_ap_set_gateway_address(ap, address_type, ip_addr);
				}

				if (rv != WIFI_ERROR_NONE)
					printf("Fail to set gateway address[%s]\n",
							__test_convert_error_to_string(rv));
			}
		}

		g_free(ap_name);
		return false;
	}

	g_free(ap_name);
	return true;
}

static bool __test_found_change_proxy_method_callback(wifi_ap_h ap, void *user_data)
{
	int rv, address_type;
	char *ap_name;
	char *ap_name_part = (char*)user_data;

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP name [%s]\n", __test_convert_error_to_string(rv));
		return false;
	}

	printf("ap_name %s, user input name %s\n", ap_name, ap_name_part);
	if (strstr(ap_name, ap_name_part) != NULL) {
		wifi_proxy_type_e type;
		char proxy_addr[65];
		int method;

		printf("Input new method type (1:direct, 2:manual, 3:auto) :\n");
		rv = scanf("%9d", &method);
		if (rv <= 0) {
			g_free(ap_name);
			return false;
		}

	       rv = test_get_user_int("Input Address type to get"
	                       "(0:IPV4, 1:IPV6):", &address_type);

	       if (rv == false || (address_type != 0 && address_type != 1)) {
	               printf("Invalid input!!\n");
	               return false;
	       }

		switch (method) {
		case 1:
			type = WIFI_PROXY_TYPE_DIRECT;
			break;
		case 2:
			type = WIFI_PROXY_TYPE_MANUAL;
			break;
		case 3:
			type = WIFI_PROXY_TYPE_AUTO;
			break;
		default:
			printf("Invalid input!\n");
			g_free(ap_name);
			return false;
		}

		rv = wifi_ap_set_proxy_type(ap, type);
		if (rv != WIFI_ERROR_NONE)
			printf("Fail to set proxy method type[%s]\n", __test_convert_error_to_string(rv));

		printf("Input new proxy address (x:skip, 0:clear) :\n");
		rv = scanf("%64s", proxy_addr);

		if (rv > 0) {
			switch (proxy_addr[0]) {
			case 'x':
				rv = WIFI_ERROR_NONE;
				break;
			case '0':
				rv = wifi_ap_set_proxy_address(ap, address_type, NULL);
				break;
			default:
				rv = wifi_ap_set_proxy_address(ap, address_type, proxy_addr);
			}

			if (rv != WIFI_ERROR_NONE)
				printf("Fail to set proxy address[%s]\n", __test_convert_error_to_string(rv));
		}

		g_free(ap_name);
		return false;
	}

	g_free(ap_name);
	return true;
}

static bool __test_found_print_ap_info_callback(wifi_ap_h ap, void *user_data)
{
	int rv, address_type = 0;
	char *ap_name;
	char *str_value;
	int int_value;
	wifi_connection_state_e conn_state;
	wifi_ip_config_type_e ip_type;
	wifi_proxy_type_e proxy_type;
	wifi_security_type_e sec_type;
	wifi_encryption_type_e enc_type;
	wifi_eap_type_e eap_type;
	wifi_eap_auth_type_e eap_auth_type;
	bool bool_value;
	char *ap_name_part = (char*)user_data;

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP name [%s]\n", __test_convert_error_to_string(rv));
		return false;
	}

	printf("ap_name %s, user input name %s\n", ap_name, ap_name_part);
	if (strstr(ap_name, ap_name_part) != NULL) {

		/* Basic info */
		printf("ESSID : %s\n", ap_name);

		if (wifi_ap_get_bssid(ap, &str_value) == WIFI_ERROR_NONE) {
			printf("BSSID : %s\n", str_value);
			g_free(str_value);
		} else
			printf("Fail to get BSSID\n");

		if (wifi_ap_get_rssi(ap, &int_value) == WIFI_ERROR_NONE)
			printf("RSSI : %d\n", int_value);
		else
			printf("Fail to get RSSI\n");

		if (wifi_ap_get_frequency(ap, &int_value) == WIFI_ERROR_NONE)
			printf("Frequency : %d\n", int_value);
		else
			printf("Fail to get Frequency\n");

		if (wifi_ap_get_max_speed(ap, &int_value) == WIFI_ERROR_NONE)
			printf("Max speed : %d\n", int_value);
		else
			printf("Fail to get Max speed\n");

		if (wifi_ap_is_favorite(ap, &bool_value) == WIFI_ERROR_NONE)
			printf("Favorite : %s\n", bool_value ? "TRUE" : "FALSE");
		else
			printf("Fail to get Favorite\n");

		/* Network info */
		if (wifi_ap_get_connection_state(ap, &conn_state) == WIFI_ERROR_NONE)
			printf("Connection State : %d\n", conn_state);
		else
			printf("Fail to get Connection State\n");

		rv = test_get_user_int("Input Address type to get"
	                       "(0:IPV4, 1:IPV6):", &address_type);

	    if (rv == false || (address_type != 0 && address_type != 1)) {
	        printf("Invalid input!!\n");
	        return false;
	    }

		if (wifi_ap_get_ip_config_type(ap, address_type, &ip_type) == WIFI_ERROR_NONE)
			printf("IP config type : %d\n", ip_type);
		else
			printf("Fail to get IP config type\n");

		if (wifi_ap_get_ip_address(ap, address_type, &str_value) == WIFI_ERROR_NONE) {
			printf("IP : %s\n", str_value);
			g_free(str_value);
		} else
			printf("Fail to get IP\n");

		if (wifi_ap_get_subnet_mask(ap, address_type, &str_value) == WIFI_ERROR_NONE) {
			printf("Subnet mask : %s\n", str_value);
			g_free(str_value);
		} else
			printf("Fail to get Subnet mask\n");

		if (wifi_ap_get_gateway_address(ap, address_type, &str_value) == WIFI_ERROR_NONE) {
			printf("Gateway : %s\n", str_value);
			g_free(str_value);
		} else
			printf("Fail to get Gateway\n");

		if (wifi_ap_get_proxy_type(ap, &proxy_type) == WIFI_ERROR_NONE)
			printf("Proxy type : %d\n", proxy_type);
		else
			printf("Fail to get Proxy type\n");

		if (wifi_ap_get_proxy_address(ap, address_type, &str_value) == WIFI_ERROR_NONE) {
			printf("Proxy : %s\n", str_value);
			g_free(str_value);
		} else
			printf("Fail to get Proxy\n");

		if (wifi_ap_get_dns_address(ap, 1, address_type, &str_value) == WIFI_ERROR_NONE) {
			printf("DNS1 : %s\n", str_value);
			g_free(str_value);
		} else
			printf("Fail to get DNS1\n");

		if (wifi_ap_get_dns_address(ap, 2, address_type, &str_value) == WIFI_ERROR_NONE) {
			printf("DNS2 : %s\n", str_value);
			g_free(str_value);
		} else
			printf("Fail to get DNS2\n");

		/* Security info */
		if (wifi_ap_get_security_type(ap, &sec_type) == WIFI_ERROR_NONE)
			printf("Security type : %d\n", sec_type);
		else
			printf("Fail to get Security type\n");

		if (wifi_ap_get_encryption_type(ap, &enc_type) == WIFI_ERROR_NONE)
			printf("Encryption type : %d\n", enc_type);
		else
			printf("Fail to get Encryption type\n");

		if (wifi_ap_is_passphrase_required(ap, &bool_value) == WIFI_ERROR_NONE)
			printf("Passphrase required : %s\n", bool_value ? "TRUE" : "FALSE");
		else
			printf("Fail to get Passphrase required\n");

		if (wifi_ap_is_wps_supported(ap, &bool_value) == WIFI_ERROR_NONE)
			printf("WPS supported : %s\n", bool_value ? "TRUE" : "FALSE");
		else
			printf("Fail to get WPS supported\n");

		if (sec_type != WIFI_SECURITY_TYPE_EAP) {
			g_free(ap_name);
			return false;
		}

		/* EAP info */
		if (wifi_ap_get_eap_type(ap, &eap_type) == WIFI_ERROR_NONE)
			printf("EAP type : %d\n", eap_type);
		else
			printf("Fail to get EAP type\n");

		if (wifi_ap_get_eap_auth_type(ap, &eap_auth_type) == WIFI_ERROR_NONE)
			printf("EAP auth type : %d\n", eap_auth_type);
		else
			printf("Fail to get EAP auth type\n");

		if (wifi_ap_get_eap_passphrase(ap, &str_value, &bool_value) == WIFI_ERROR_NONE) {
			printf("EAP user name : %s\n", str_value);
			printf("EAP is password setted : %s\n", bool_value ? "TRUE" : "FALSE");
			g_free(str_value);
		} else
			printf("Fail to get EAP passphrase(user name/password)\n");

		if (wifi_ap_get_eap_ca_cert_file(ap, &str_value) == WIFI_ERROR_NONE) {
			printf("EAP ca cert file : %s\n", str_value);
			g_free(str_value);
		} else
			printf("Fail to get EAP ca cert file\n");

		if (wifi_ap_get_eap_client_cert_file(ap, &str_value) == WIFI_ERROR_NONE) {
			printf("EAP client cert file : %s\n", str_value);
			g_free(str_value);
		} else
			printf("Fail to get EAP client cert file\n");

		if (wifi_ap_get_eap_private_key_file(ap, &str_value) == WIFI_ERROR_NONE) {
			printf("EAP private key file : %s\n", str_value);
			g_free(str_value);
		} else
			printf("Fail to get EAP private key file\n");

		g_free(ap_name);
		return false;
	}

	g_free(ap_name);
	return true;
}

static bool _test_config_list_cb(const wifi_config_h config, void *user_data)
{
	gchar *name = NULL;
	wifi_security_type_e security_type;

	wifi_config_get_name(config, &name);
	wifi_config_get_security_type(config, &security_type);

	printf("Name[%s] ", name);
	printf("Security type[%d] ", security_type);
	if (security_type == WIFI_SECURITY_TYPE_EAP) {
		wifi_eap_type_e eap_type;
		wifi_eap_auth_type_e eap_auth_type;
		wifi_config_get_eap_type(config, &eap_type);
		printf("Eap type[%d] ", eap_type);
		wifi_config_get_eap_auth_type(config, &eap_auth_type);
		printf("Eap auth type[%d]", eap_auth_type);
	}
	printf("\n");

	g_free(name);

	return true;
}

static bool __test_found_specific_aps_callback(wifi_ap_h ap, void *user_data)
{
	printf("Found specific ap Completed\n");

	int rv;
	char *ap_name = NULL;
	wifi_security_type_e security_type = WIFI_SECURITY_TYPE_NONE;

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP name [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}
	printf("[AP name] : %s\n", ap_name);

	rv = wifi_ap_get_security_type(ap, &security_type);
	if (rv == WIFI_ERROR_NONE)
		printf("[Security type] : %d\n", security_type);
	else {
		printf("Fail to get Security type\n");
		g_free(ap_name);
		return false;
	}

	switch(security_type) {
	case WIFI_SECURITY_TYPE_WEP :
	case WIFI_SECURITY_TYPE_WPA_PSK :
	case WIFI_SECURITY_TYPE_WPA2_PSK :
		{
			char passphrase[100];
			printf("Input passphrase for %s : ", ap_name);
			rv = scanf("%99s", passphrase);

			rv = wifi_ap_set_passphrase(ap, passphrase);
			if (rv != WIFI_ERROR_NONE) {
				printf("Fail to set passphrase : %s\n", __test_convert_error_to_string(rv));
				g_free(ap_name);
				return false;
			}
		}
		break;
	case WIFI_SECURITY_TYPE_EAP :
		{
			char input_str1[100];
			printf("Input user name for %s : ", ap_name);
			rv = scanf("%99s", input_str1);

			char input_str2[100];
			printf("Input password for %s : ", ap_name);
			rv = scanf("%99s", input_str2);

			rv = wifi_ap_set_eap_passphrase(ap, input_str1, input_str2);
			if (rv != WIFI_ERROR_NONE) {
				printf("Fail to set eap passphrase : %s\n", __test_convert_error_to_string(rv));
				g_free(ap_name);
				return false;
			}

			char *inputed_name = NULL;
			bool is_pass_set;
			rv = wifi_ap_get_eap_passphrase(ap, &inputed_name, &is_pass_set);
			if (rv != WIFI_ERROR_NONE) {
				printf("Fail to get eap passphrase : %s\n", __test_convert_error_to_string(rv));
				g_free(ap_name);
				return false;
			}

			printf("name : %s, is password set : %s\n", inputed_name, is_pass_set ? "TRUE" : "FALSE");
			g_free(inputed_name);
		}
		break;
	case WIFI_SECURITY_TYPE_NONE :
	default :
		break;
	}

	rv = wifi_connect(ap, __test_connected_callback, NULL);
	if (rv != WIFI_ERROR_NONE)
		printf("Fail to connection request [%s] : %s\n", ap_name, __test_convert_error_to_string(rv));
	else
		printf("Success to connection request [%s]\n", ap_name);

	g_free(ap_name);
	return true;
}

static void __test_scan_specific_ap_callback(wifi_error_e error_code, void* user_data)
{
	int rv;

	printf("Specific scan Completed from scan request, error code : %s\n",
			__test_convert_error_to_string(error_code));

	if (error_code != WIFI_ERROR_NONE)
		return;

	rv = wifi_foreach_found_specific_aps(__test_found_specific_aps_callback, user_data);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get specific AP(can't get AP list) [%s]\n", __test_convert_error_to_string(rv));
		return;
	}
}

int test_wifi_init(void)
{
	int rv = wifi_initialize();

	if (rv == WIFI_ERROR_NONE) {
		wifi_set_device_state_changed_cb(__test_device_state_callback, NULL);
		wifi_set_background_scan_cb(__test_bg_scan_completed_callback, NULL);
		wifi_set_connection_state_changed_cb(__test_connection_state_callback, NULL);
		wifi_set_rssi_level_changed_cb(__test_rssi_level_callback, NULL);
	} else {
		printf("Wifi init failed [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Wifi init succeeded\n");
	return 1;
}

int  test_wifi_deinit(void)
{
	int rv = 0;

	rv = wifi_deinitialize();

	if (rv != WIFI_ERROR_NONE){
		printf("Wifi deinit failed [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Wifi deinit succeeded\n");
	return 1;
}

int test_wifi_activate(void)
{
	int rv = 0;

	rv = wifi_activate(__test_activated_callback, NULL);

	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to activate Wi-Fi device [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success to activate Wi-Fi device\n");

	return 1;
}

int test_wifi_deactivate(void)
{
	int rv = 0;

	rv = wifi_deactivate(__test_deactivated_callback, NULL);

	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to deactivate Wi-Fi device [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success to deactivate Wi-Fi device\n");

	return 1;
}

int test_is_activated(void)
{
	int rv = 0;
	bool state = false;

	rv = wifi_is_activated(&state);

	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get Wi-Fi device state [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success to get Wi-Fi device state : %s\n", (state) ? "TRUE" : "FALSE");

	return 1;
}

int test_get_connection_state(void)
{
	int rv = 0;
	wifi_connection_state_e connection_state;

	rv = wifi_get_connection_state(&connection_state);

	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get connection state [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Success to get connection state : ");
	switch (connection_state) {
	case WIFI_CONNECTION_STATE_ASSOCIATION:
		printf("Association\n");
		break;
	case WIFI_CONNECTION_STATE_CONNECTED:
		printf("Connected\n");
		break;
	case WIFI_CONNECTION_STATE_CONFIGURATION:
		printf("Configuration\n");
		break;
	case WIFI_CONNECTION_STATE_DISCONNECTED:
		printf("Disconnected\n");
		break;
	default:
		printf("Unknown\n");
	}

	return 1;
}

int test_get_mac_address(void)
{
	int rv = 0;
	char *mac_addr = NULL;

	rv = wifi_get_mac_address(&mac_addr);

	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get MAC address [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("MAC address : %s\n", mac_addr);
	g_free(mac_addr);

	return 1;
}

int test_get_interface_name(void)
{
	int rv = 0;
	char *if_name = NULL;

	rv = wifi_get_network_interface_name(&if_name);

	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get Interface name [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Interface name : %s\n", if_name);
	g_free(if_name);

	return 1;
}

int test_scan_request(void)
{
	int rv = 0;

	rv = wifi_scan(__test_scan_request_callback, NULL);

	if (rv != WIFI_ERROR_NONE) {
		printf("Scan request failed [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Scan request succeeded\n");

	return 1;
}

int test_get_connected_ap(void)
{
	int rv = 0;
	char *ap_name = NULL;
	wifi_ap_h ap_h;

	rv = wifi_get_connected_ap(&ap_h);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get connected AP [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	rv = wifi_ap_get_essid(ap_h, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get essid [%s]\n", __test_convert_error_to_string(rv));
		wifi_ap_destroy(ap_h);
		return -1;
	}

	printf("Connected AP : %s\n", ap_name);
	g_free(ap_name);
	wifi_ap_destroy(ap_h);

	return 1;
}

int test_foreach_found_aps(void)
{
	int rv = 0;

	rv = wifi_foreach_found_aps(__test_found_ap_callback, NULL);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP list [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Get AP list finished\n");

	return 1;
}

int test_connect_ap(void)
{
	int rv = 0;
	char ap_name[33];
	bool state = false;

	wifi_is_activated(&state);
	if (state == false)
		return -1;

	printf("Input a part of AP name to connect : ");
	rv = scanf("%32s", ap_name);

	rv = wifi_foreach_found_aps(__test_found_connect_ap_callback, ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to connect (can't get AP list) [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Connection step finished\n");
	return 1;
}

int test_connect_specific_ap(void)
{
	int rv;
	char ap_name[33];

	printf("Input a part of specific AP name to connect : ");
	rv = scanf("%32s", ap_name);
	if (rv <= 0)
		return -1;

	rv = wifi_scan_specific_ap(ap_name, __test_scan_specific_ap_callback, NULL);

	if (rv != WIFI_ERROR_NONE) {
		printf("Scan request failed [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Scan specific AP request succeeded\n");
	return 1;
}

int test_disconnect_ap(void)
{
	int rv = 0;
	char ap_name[33];
	bool state = false;

	wifi_is_activated(&state);
	if (state == false)
		return -1;

	printf("Input a part of AP name to disconnect : ");
	rv = scanf("%32s", ap_name);

	rv = wifi_foreach_found_aps(__test_found_disconnect_ap_callback, ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to disconnect (can't get AP list) [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Disconnection step finished\n");
	return 1;
}

int test_connect_wps(void)
{
	int rv = 0;
	char ap_name[33];
	bool state = false;

	wifi_is_activated(&state);
	if (state == false)
		return -1;

	printf("Input a part of AP name to connect by wps : ");
	rv = scanf("%32s", ap_name);

	rv = wifi_foreach_found_aps(__test_found_connect_wps_callback, ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to connect (can't get AP list) [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Connection step finished\n");
	return 1;
}

int test_forget_ap(void)
{
	int rv = 0;
	char ap_name[33];
	bool state = false;

	wifi_is_activated(&state);
	if (state == false)
		return -1;

	printf("Input a part of AP name to forget : ");
	rv = scanf("%32s", ap_name);

	rv = wifi_foreach_found_aps(__test_found_forget_ap_callback, ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to forget (can't get AP list) [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Forget AP finished\n");
	return 1;
}

int test_connect_eap_ap(void)
{
	int rv = 0;
	char ap_name[33];
	bool state = false;

	wifi_is_activated(&state);
	if (state == false)
		return -1;

	printf("Input a part of AP name to connect : ");
	rv = scanf("%32s", ap_name);

	rv = wifi_foreach_found_aps(__test_found_eap_ap_callback, ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to connect (can't get AP list) [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Connection step finished\n");
	return 1;
}

int test_set_ip_method(void)
{
	int rv;
	char ap_name[33];
	bool state;

	rv = wifi_is_activated(&state);
	if (rv != WIFI_ERROR_NONE || state == false)
		return -1;

	printf("Input a part of AP name to change IP method : ");
	rv = scanf("%32s", ap_name);
	if (rv <= 0)
		return -1;

	rv = wifi_foreach_found_aps(__test_found_change_ip_method_callback, ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to change (can't get AP list) [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("IP method changing finished\n");
	return 1;
}

int test_set_proxy_method(void)
{
	int rv;
	char ap_name[33];
	bool state;

	rv = wifi_is_activated(&state);
	if (rv != WIFI_ERROR_NONE || state == false)
		return -1;

	printf("Input a part of AP name to change Proxy method : ");
	rv = scanf("%32s", ap_name);
	if (rv <= 0)
		return -1;

	rv = wifi_foreach_found_aps(__test_found_change_proxy_method_callback, ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to change (can't get AP list) [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("Proxy method changing finished\n");
	return 1;
}

int test_get_ap_info(void)
{
	int rv;
	char ap_name[33];
	bool state;

	rv = wifi_is_activated(&state);
	if (rv != WIFI_ERROR_NONE || state == false)
		return -1;

	printf("Input a part of AP name to get detailed info : ");
	rv = scanf("%32s", ap_name);
	if (rv <= 0)
		return -1;

	rv = wifi_foreach_found_aps(__test_found_print_ap_info_callback, ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get AP info (can't get AP list) [%s]\n", __test_convert_error_to_string(rv));
		return -1;
	}

	printf("AP info printing finished\n");
	return 1;
}

int test_load_configuration(void)
{
	int rv;

	rv = wifi_config_foreach_configuration(_test_config_list_cb, NULL);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	return 1;
}

int test_save_configuration(void)
{
	int rv;
	char name[33] = { 0, };
	char passphrase[100] = { 0, };
	int type = 0;
	wifi_config_h config;

	printf("Input AP configuration\n");
	printf("Name : ");
	rv = scanf("%32s", name);
	if (rv <= 0)
		return -1;

	printf("Passphrase : ");
	rv = scanf("%99s", passphrase);
	if (rv <= 0)
		return -1;

	printf("Security type(None(0), WEP(1), WPA-PSK(2), EAP(4) : ");
	rv = scanf("%d", &type);
	if (rv <= 0)
		return -1;

	rv = wifi_config_create(name, passphrase, type, &config);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	rv = wifi_config_save_configuration(config);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	rv = wifi_config_destroy(config);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	return 1;
}

int test_set_configuration_proxy_and_hidden(void)
{
	int rv;
	char name[33] = { 0, };
	char passphrase[100] = { 0, };
	int type = 0;
	char proxy[100] = { 0, };
	int hidden = 0;
	wifi_config_h config;

	printf("Input AP configuration\n");
	printf("Name : ");
	rv = scanf("%32s", name);
	if (rv <= 0)
		return -1;

	printf("Passphrase : ");
	rv = scanf("%99s", passphrase);
	if (rv <= 0)
		return -1;

	printf("Security type(None(0), WEP(1), WPA-PSK(2), EAP(4) : ");
	rv = scanf("%d", &type);
	if (rv <= 0)
		return -1;

	printf("Proxy(server:port) : ");
	rv = scanf("%99s", proxy);
	if (rv <= 0)
		return -1;

	printf("Hidden(1:Hidden) : ");
	rv = scanf("%d", &hidden);
	if (rv <= 0)
		return -1;

	rv = wifi_config_create(name, passphrase, type, &config);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	rv = wifi_config_save_configuration(config);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	rv = wifi_config_set_proxy_address(config, WIFI_ADDRESS_FAMILY_IPV4, proxy);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	if (hidden == 1)
		rv = wifi_config_set_hidden_ap_property(config, TRUE);
	else
		rv = wifi_config_set_hidden_ap_property(config, FALSE);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	rv = wifi_config_destroy(config);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	return 1;
}

int test_set_eap_configuration(void)
{
	int rv;
	char name[33] = { 0, };
	char passphrase[100] = { 0, };
	int type = WIFI_SECURITY_TYPE_EAP;
	wifi_config_h config;

	printf("Input EAP configuration\n");
	printf("Name : ");
	rv = scanf("%32s", name);
	if (rv <= 0)
		return -1;

	printf("Passphrase : ");
	rv = scanf("%99s", passphrase);
	if (rv <= 0)
		return -1;

	rv = wifi_config_create(name, passphrase, type, &config);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	rv = wifi_config_save_configuration(config);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	rv = wifi_config_set_eap_type(config, WIFI_EAP_TYPE_TLS);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	rv = wifi_config_set_eap_auth_type(config, WIFI_EAP_AUTH_TYPE_MD5);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	rv = wifi_config_destroy(config);
	if (rv != WIFI_ERROR_NONE)
		return -1;

	return 1;
}

int main(int argc, char **argv)
{
	GMainLoop *mainloop;
	g_type_init();
	mainloop = g_main_loop_new (NULL, FALSE);

	GIOChannel *channel = g_io_channel_unix_new(0);
	g_io_add_watch(channel, (G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL), test_thread, NULL);

	printf("Test Thread created...\n");

	g_main_loop_run (mainloop);

	return 0;
}

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data)
{
	int rv;
	char a[10];

	printf("Event received from stdin\n");

	rv = read(0, a, 10);

	if (rv <= 0 || a[0] == '0') {
		rv = wifi_deinitialize();

		if (rv != WIFI_ERROR_NONE)
			printf("Fail to deinitialize.\n");

		exit(1);
	}

	if (a[0] == '\n' || a[0] == '\r') {
		printf("\n\n Network Connection API Test App\n\n");
		printf("Options..\n");
		printf("1 	- Wi-Fi init and set callbacks\n");
		printf("2 	- Wi-Fi deinit(unset callbacks automatically)\n");
		printf("3	- Activate Wi-Fi device\n");
		printf("4 	- Deactivate Wi-Fi device\n");
		printf("5 	- Is Wi-Fi activated?\n");
		printf("6	- Get connection state\n");
		printf("7 	- Get MAC address\n");
		printf("8 	- Get Wi-Fi interface name\n");
		printf("9 	- Scan request\n");
		printf("a 	- Get Connected AP\n");
		printf("b 	- Get AP list\n");
		printf("c 	- Connect\n");
		printf("d 	- Disconnect\n");
		printf("e 	- Connect by wps pbc\n");
		printf("f 	- Forget an AP\n");
		printf("g 	- Set & connect EAP\n");
		printf("h 	- Set IP method type\n");
		printf("i 	- Set Proxy method type\n");
		printf("j 	- Get Ap info\n");
		printf("k 	- Connect Specific AP\n");
		printf("l 	- Load configuration\n");
		printf("m 	- Save configuration\n");
		printf("n 	- Set configuration proxy and hidden\n");
		printf("o       - Set EAP configuration\n");
		printf("0 	- Exit \n");

		printf("ENTER  - Show options menu.......\n");
	}

	switch (a[0]) {
	case '1':
		rv = test_wifi_init();
		break;
	case '2':
		rv = test_wifi_deinit();
		break;
	case '3':
		rv = test_wifi_activate();
		break;
	case '4':
		rv = test_wifi_deactivate();
		break;
	case '5':
		rv = test_is_activated();
		break;
	case '6':
		rv = test_get_connection_state();
		break;
	case '7':
		rv = test_get_mac_address();
		break;
	case '8':
		rv = test_get_interface_name();
		break;
	case '9':
		rv = test_scan_request();
		break;
	case 'a':
		rv = test_get_connected_ap();
		break;
	case 'b':
		rv = test_foreach_found_aps();
		break;
	case 'c':
		rv = test_connect_ap();
		break;
	case 'd':
		rv = test_disconnect_ap();
		break;
	case 'e':
		rv = test_connect_wps();
		break;
	case 'f':
		rv = test_forget_ap();
		break;
	case 'g':
		rv = test_connect_eap_ap();
		break;
	case 'h':
		rv = test_set_ip_method();
		break;
	case 'i':
		rv = test_set_proxy_method();
		break;
	case 'j':
		rv = test_get_ap_info();
		break;
	case 'k':
		rv = test_connect_specific_ap();
		break;
	case 'l':
		rv = test_load_configuration();
		break;
	case 'm':
		rv = test_save_configuration();
		break;
	case 'n':
		rv = test_set_configuration_proxy_and_hidden();
		break;
	case 'o':
		rv = test_set_eap_configuration();
		break;

	default:
		break;
	}

	if (rv == 1)
		printf("Operation succeeded!\n");
	else
		printf("Operation failed!\n");

	return TRUE;
}

