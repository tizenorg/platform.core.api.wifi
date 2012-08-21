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
#include "assert.h"
#include "glib.h"
#include <wifi.h>
#include <tizen_error.h>


gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data);


static void __test_device_state_callback(wifi_error_e error_code, wifi_device_state_e state, bool is_requested, void* user_data)
{
	printf("Device state changed callback, error code : %d, requested : %d", error_code, is_requested);

	if (state == WIFI_DEVICE_STATE_ACTIVATED)
		printf(", state : Activated\n");
	else
		printf(", state : Deactivated\n");
}

static void __test_bg_scan_completed_callback(wifi_error_e error_code, void* user_data)
{
	printf("Background Scan Completed, error code : %d\n", error_code);
}

static void __test_scan_request_callback(wifi_error_e error_code, void* user_data)
{
	printf("Scan Completed from scan request, error code : %d\n", error_code);
}

static void __test_connection_state_callback(wifi_error_e error_code, wifi_connection_state_e state, wifi_ap_h ap, bool is_requested, void* user_data)
{
	int rv = 0;
	char *ap_name = NULL;

	printf("Connection state changed callback, error code : %d, requested : %d", error_code, is_requested);

	switch (state) {
	case WIFI_CONNECTION_STATE_CONNECTING:
		printf(", state : Connecting");
		break;
	case WIFI_CONNECTION_STATE_CONNECTED:
		printf(", state : Connected");
		break;
	case WIFI_CONNECTION_STATE_DISCONNECTING:
		printf(", state : Disconnecting");
		break;
	case WIFI_CONNECTION_STATE_DISCONNECTED:
		printf(", state : Disconnected");
		break;
	}

	rv = wifi_ap_get_essid(ap, &ap_name);
	if (rv != WIFI_ERROR_NONE)
		printf(", Fail to get AP name [%d]\n", rv);
	else {
		printf(", AP name : %s\n", ap_name);
		g_free(ap_name);
	}
}

static void __test_rssi_level_callback(wifi_rssi_level_e rssi_level, void* user_data)
{
	printf("RSSI level changed callback, level = %d\n", rssi_level);
}

static const char* __test_print_state(wifi_connection_state_e state)
{
	switch (state) {
	case WIFI_CONNECTION_STATE_DISCONNECTED:
		return "Disconnected";
	case WIFI_CONNECTION_STATE_CONNECTING:
		return "Connecting";
	case WIFI_CONNECTION_STATE_CONNECTED:
		return "Connected";
	case WIFI_CONNECTION_STATE_DISCONNECTING:
		return "Disconnecting";
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
		printf("Fail to get AP name [%d]\n", rv);
		return false;
	}

	rv = wifi_ap_get_connection_state(ap, &state);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get State [%d]\n", rv);
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
		printf("Fail to get AP name [%d]\n", rv);
		return false;
	}

	if (strstr(ap_name, ap_name_part) != NULL) {
		bool required = false;
		wifi_ap_is_passphrase_required(ap, &required);

		if (required) {
			char passphrase[100];
			printf("Input passphrase for %s : ", ap_name);
			rv = scanf("%100s", passphrase);

			rv = wifi_ap_set_passphrase(ap, passphrase);
			if (rv != WIFI_ERROR_NONE) {
				printf("Fail to set passphrase : %d\n", rv);
				g_free(ap_name);
				return false;
			}
		}

		rv = wifi_connect(ap);
		if (rv != WIFI_ERROR_NONE)
			printf("Fail to connect [%s] : %d\n", ap_name, rv);
		else
			printf("Success to connect [%s]\n", ap_name);

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
		printf("Fail to get AP name [%d]\n", rv);
		return false;
	}

	if (strstr(ap_name, ap_name_part) != NULL) {
		rv = wifi_disconnect(ap);
		if (rv != WIFI_ERROR_NONE)
			printf("Fail to disconnect %s : [%d]\n", ap_name, rv);
		else
			printf("Success to disconnect %s\n", ap_name);

		g_free(ap_name);
		return false;
	}

	g_free(ap_name);
	return true;
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
		printf("Wifi init failed [%d]\n", rv);
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
		printf("Wifi deinit failed [%d]\n", rv);
		return -1;
	}

	printf("Wifi deinit succeeded\n");
	return 1;
}

int test_wifi_activate(void)
{
	int rv = 0;

	rv = wifi_activate();

	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to activate Wi-Fi device [%d]\n", rv);
		return -1;
	}

	printf("Success to activate Wi-Fi device\n");

	return 1;
}

int test_wifi_deactivate(void)
{
	int rv = 0;

	rv = wifi_deactivate();

	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to deactivate Wi-Fi device [%d]\n", rv);
		return -1;
	}

	printf("Success to deactivate Wi-Fi device\n");

	return 1;
}

int test_is_activated(void)
{
	int rv = 0;
	bool state;

	rv = wifi_is_activated(&state);

	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get Wi-Fi device state [%d]\n", rv);
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
		printf("Fail to get connection state [%d]\n", rv);
		return -1;
	}

	printf("Success to get connection state : ");
	switch (connection_state) {
	case WIFI_CONNECTION_STATE_CONNECTING:
		printf("Connecting\n");
		break;
	case WIFI_CONNECTION_STATE_CONNECTED:
		printf("Connected\n");
		break;
	case WIFI_CONNECTION_STATE_DISCONNECTING:
		printf("Disconnecting\n");
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
		printf("Fail to get MAC address [%d]\n", rv);
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
		printf("Fail to get Interface name [%d]\n", rv);
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
		printf("Scan request failed [%d]\n", rv);
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
		printf("Fail to get connected AP [%d]\n", rv);
		return -1;
	}

	rv = wifi_ap_get_essid(ap_h, &ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to get connected AP [%d]\n", rv);
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
		printf("Fail to get AP list [%d]\n", rv);
		return -1;
	}

	printf("Get AP list finished\n");

	return 1;
}

int test_connect_ap(void)
{
	int rv = 0;
	char ap_name[32];

	printf("Input a part of AP name to connect : ");
	rv = scanf("%32s", ap_name);

	rv = wifi_foreach_found_aps(__test_found_connect_ap_callback, ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to connect (can't get AP list) [%d]\n", rv);
		return -1;
	}

	printf("Connection step finished\n");
	return 1;
}

int test_disconnect_ap(void)
{
	int rv = 0;
	char ap_name[32];

	printf("Input a part of AP name to disconnect : ");
	rv = scanf("%32s", ap_name);

	rv = wifi_foreach_found_aps(__test_found_disconnect_ap_callback, ap_name);
	if (rv != WIFI_ERROR_NONE) {
		printf("Fail to disconnect (can't get AP list) [%d]\n", rv);
		return -1;
	}

	printf("Disconnection step finished\n");
	return 1;
}

int main(int argc, char **argv)
{
	GMainLoop *mainloop;
	mainloop = g_main_loop_new (NULL, FALSE);

	GIOChannel *channel = g_io_channel_unix_new(0);
	g_io_add_watch(channel, (G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL), test_thread,NULL );

	printf("Test Thread created...\n");

	g_main_loop_run (mainloop);

	return 0;
}

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data)
{
	int rv = 0;
	char a[100];

	memset(a, '\0', 100);
	printf("Event received from stdin\n");

	rv = read(0, a, 100);

	if (rv < 0 || a[0] == '0') exit(1);

	if (*a == '\n' || *a == '\r'){
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
		printf("0 	- Exit \n");

		printf("ENTER  - Show options menu.......\n");
	}

	switch (a[0]) {
		case '1': {
			rv = test_wifi_init();
		} break;
		case '2': {
			rv = test_wifi_deinit();
		} break;
		case '3': {
			rv = test_wifi_activate();
		} break;
		case '4': {
			rv = test_wifi_deactivate();
		} break;
		case '5': {
			rv = test_is_activated();
		} break;
		case '6': {
			rv = test_get_connection_state();
		} break;
		case '7': {
			rv = test_get_mac_address();
		} break;
		case '8': {
			rv = test_get_interface_name();
		} break;
		case '9': {
			rv = test_scan_request();
		} break;
		case 'a': {
			rv = test_get_connected_ap();
		} break;
		case 'b': {
			rv = test_foreach_found_aps();
		} break;
		case 'c': {
			rv = test_connect_ap();
		} break;
		case 'd': {
			rv = test_disconnect_ap();
		} break;
	}
	return TRUE;
}

