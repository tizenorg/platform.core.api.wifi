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

#ifndef __TIZEN_NETWORK_WIFI_H__
#define __TIZEN_NETWORK_WIFI_H__

#include <tizen.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file wifi.h
 */

/**
* @addtogroup CAPI_NETWORK_WIFI_MANAGER_MODULE
* @{
*/

/**
 * @brief Enumeration for the Wi-Fi error type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
    WIFI_ERROR_NONE = TIZEN_ERROR_NONE, 						/**< Successful */
    WIFI_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER, 			/**< Invalid parameter */
    WIFI_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY, 				/**< Out of memory error */
    WIFI_ERROR_INVALID_OPERATION = TIZEN_ERROR_INVALID_OPERATION, 			/**< Invalid operation */
    WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED = TIZEN_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED, /**< Address family not supported */
    WIFI_ERROR_OPERATION_FAILED = TIZEN_ERROR_WIFI|0x0301, 				/**< Operation failed */
    WIFI_ERROR_NO_CONNECTION = TIZEN_ERROR_WIFI|0x0302, 				/**< There is no connected AP */
    WIFI_ERROR_NOW_IN_PROGRESS = TIZEN_ERROR_NOW_IN_PROGRESS, 				/**< Now in progress */
    WIFI_ERROR_ALREADY_EXISTS = TIZEN_ERROR_WIFI|0x0303, 				/**< Already exists */
    WIFI_ERROR_OPERATION_ABORTED = TIZEN_ERROR_WIFI|0x0304, 				/**< Operation is aborted */
    WIFI_ERROR_DHCP_FAILED = TIZEN_ERROR_WIFI|0x0306, 					/**< DHCP failed */
    WIFI_ERROR_INVALID_KEY = TIZEN_ERROR_WIFI|0x0307,					/**< Invalid key */
    WIFI_ERROR_NO_REPLY = TIZEN_ERROR_WIFI|0x0308, 					/**< No reply */
    WIFI_ERROR_SECURITY_RESTRICTED = TIZEN_ERROR_WIFI|0x0309, 				/**< Restricted by security system policy */
    WIFI_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED, 			/**< Permission Denied */
    WIFI_ERROR_NOT_SUPPORTED = TIZEN_ERROR_NOT_SUPPORTED                /**< Not Supported */
} wifi_error_e;

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_MONITOR_MODULE
* @{
*/

/**
 * @brief Enumeration for the state of the Wi-Fi device.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
    WIFI_DEVICE_STATE_DEACTIVATED = 0,  /**< Wi-Fi is Deactivated */
    WIFI_DEVICE_STATE_ACTIVATED = 1, 	/**< Wi-Fi is activated */
} wifi_device_state_e;

/**
 * @brief Enumeration for the state of the Wi-Fi connection.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
	WIFI_CONNECTION_STATE_FAILURE = -1,		/**< Connection failed state */
	WIFI_CONNECTION_STATE_DISCONNECTED = 0,		/**< Disconnected state */
	WIFI_CONNECTION_STATE_ASSOCIATION = 1,		/**< Association state */
	WIFI_CONNECTION_STATE_CONFIGURATION = 2,	/**< Configuration state */
	WIFI_CONNECTION_STATE_CONNECTED = 3,		/**< Connected state */
} wifi_connection_state_e;

/**
 * @brief Enumeration for the RSSI level.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
    WIFI_RSSI_LEVEL_0 = 0,  /**< level 0 */
    WIFI_RSSI_LEVEL_1 = 1,  /**< level 1 */
    WIFI_RSSI_LEVEL_2 = 2,  /**< level 2 */
    WIFI_RSSI_LEVEL_3 = 3,  /**< level 3 */
    WIFI_RSSI_LEVEL_4 = 4,  /**< level 4 */
} wifi_rssi_level_e;

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_AP_NETWORK_MODULE
* @{
*/

/**
 * @brief Enumeration for the Net IP configuration type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
    WIFI_IP_CONFIG_TYPE_NONE = 0,    	/**< Not defined */
    WIFI_IP_CONFIG_TYPE_STATIC  = 1,  	/**< Manual IP configuration */
    WIFI_IP_CONFIG_TYPE_DYNAMIC = 2,  	/**< Config IP using DHCP client*/
    WIFI_IP_CONFIG_TYPE_AUTO = 3,  	/**< Config IP from Auto IP pool (169.254/16). Later with DHCP client, if available */
    WIFI_IP_CONFIG_TYPE_FIXED = 4,  	/**< Indicates an IP address that can not be modified */
} wifi_ip_config_type_e;

/**
 * @brief Enumeration for the address type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
    WIFI_ADDRESS_FAMILY_IPV4 = 0,  /**< IPV4 Address family */
    WIFI_ADDRESS_FAMILY_IPV6 = 1,  /**< IPV6 Address family */
} wifi_address_family_e;

/**
 * @brief Enumeration for the proxy method type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
    WIFI_PROXY_TYPE_DIRECT = 0,	/**< Direct connection */
    WIFI_PROXY_TYPE_AUTO = 1,	/**< Auto configuration(Use PAC file). If URL property is not set, DHCP/WPAD auto-discover will be tried */
    WIFI_PROXY_TYPE_MANUAL  = 2	/**< Manual configuration */
} wifi_proxy_type_e;

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_AP_SECURITY_MODULE
* @{
*/

/**
 * @brief Enumeration for Wi-Fi security type.
 * @details The following security modes are used in infrastructure and ad-hoc mode.
 * For now all EAP security mechanisms are provided only in infrastructure mode.
 *
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
    WIFI_SECURITY_TYPE_NONE = 0,  	/**< Security disabled */
    WIFI_SECURITY_TYPE_WEP = 1,  	/**< WEP */
    WIFI_SECURITY_TYPE_WPA_PSK = 2,  	/**< WPA-PSK */
    WIFI_SECURITY_TYPE_WPA2_PSK = 3,  	/**< WPA2-PSK */
    WIFI_SECURITY_TYPE_EAP = 4,  	/**< EAP */
} wifi_security_type_e;

/**
 * @brief Enumeration for Wi-Fi encryption type.
 * @details The following encryption modes are used in infrastructure and ad-hoc mode.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
    WIFI_ENCRYPTION_TYPE_NONE = 0,  		/**< Encryption disabled */
    WIFI_ENCRYPTION_TYPE_WEP = 1,  		/**< WEP */
    WIFI_ENCRYPTION_TYPE_TKIP = 2,  		/**< TKIP */
    WIFI_ENCRYPTION_TYPE_AES = 3,  		/**< AES */
    WIFI_ENCRYPTION_TYPE_TKIP_AES_MIXED = 4,	/**< TKIP and AES are both supported */
} wifi_encryption_type_e;

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_AP_SECURITY_EAP_MODULE
* @{
*/

/**
 * @brief Enumeration for EAP type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
    WIFI_EAP_TYPE_PEAP = 0,	/**< EAP PEAP type */
    WIFI_EAP_TYPE_TLS = 1,	/**< EAP TLS type */
    WIFI_EAP_TYPE_TTLS = 2,	/**< EAP TTLS type */
    WIFI_EAP_TYPE_SIM = 3,	/**< EAP SIM type */
    WIFI_EAP_TYPE_AKA = 4,	/**< EAP AKA type */
} wifi_eap_type_e;

/**
 * @brief Enumeration for EAP phase2 authentication type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef enum
{
    WIFI_EAP_AUTH_TYPE_NONE = 0,  	/**< EAP phase2 authentication none */
    WIFI_EAP_AUTH_TYPE_PAP = 1,  	/**< EAP phase2 authentication PAP */
    WIFI_EAP_AUTH_TYPE_MSCHAP = 2,	/**< EAP phase2 authentication MSCHAP */
    WIFI_EAP_AUTH_TYPE_MSCHAPV2 = 3,	/**< EAP phase2 authentication MSCHAPv2 */
    WIFI_EAP_AUTH_TYPE_GTC = 4,		/**< EAP phase2 authentication GTC */
    WIFI_EAP_AUTH_TYPE_MD5 = 5,		/**< EAP phase2 authentication MD5 */
} wifi_eap_auth_type_e;

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_AP_MODULE
* @{
*/

/**
 * @brief The Wi-Fi access point handle.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 */
typedef void* wifi_ap_h;

/**
* @}
*/

/**
* @addtogroup CAPI_NETWORK_WIFI_CONFIG_MODULE
* @{
*/

/**
 * @brief The Wi-Fi access point configuration handle
 * @since_tizen 2.4
 */
typedef void *wifi_config_h;

/**
* @}
*/

/**
* @addtogroup CAPI_NETWORK_WIFI_MANAGER_MODULE
* @{
*/

/**
 * @brief Called when you get the found access point repeatedly.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks @a ap is valid only in this function. In order to use @a ap outside this function, you must copy the ap with wifi_ap_clone().
 * @param[in]  ap  The access point
 * @param[in]  user_data  The user data passed from the request function
 * @return  @c true to continue with the next iteration of the loop, \n
 *	    otherwise @c false to break out of the loop
 * @pre  wifi_foreach_found_aps() will invoke this callback.
 * @pre  wifi_foreach_found_specific_aps() will invoke this callback.
 * @see  wifi_foreach_found_aps()
 * @see  wifi_foreach_found_specific_aps()
 */
typedef bool(*wifi_found_ap_cb)(wifi_ap_h ap, void *user_data);

/**
 * @brief Called when the scan is finished.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] error_code  The error code
 * @param[in] user_data The user data passed from the callback registration function
 * @see wifi_scan()
 * @see wifi_set_background_scan_cb()
 * @see wifi_unset_background_scan_cb()
 */
typedef void(*wifi_scan_finished_cb)(wifi_error_e error_code, void *user_data);

/**
 * @brief Called after wifi_activate() or wifi_activate_with_wifi_picker_tested() is completed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] result  The result
 * @param[in] user_data The user data passed from wifi_activate() and wifi_activate_with_wifi_picker_tested()
 * @pre wifi_activate() or wifi_activate_with_wifi_picker_tested() will invoke this callback function.
 * @see wifi_activate()
 * @see wifi_activate_with_wifi_picker_tested()
 */
typedef void(*wifi_activated_cb)(wifi_error_e result, void *user_data);

/**
 * @brief Called after wifi_deactivate() is completed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] result  The result
 * @param[in] user_data The user data passed from wifi_deactivate()
 * @pre wifi_deactivate() will invoke this callback function.
 * @see wifi_deactivate()
 */
typedef void(*wifi_deactivated_cb)(wifi_error_e result, void *user_data);

/**
 * @brief Called after either wifi_connect() or wifi_connect_by_wps_pbc() or wifi_connect_by_wps_pin() are completed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] result  The result
 * @param[in] user_data The user data passed from either wifi_connect() or wifi_connect_by_wps_pbc() or wifi_connect_by_wps_pin()
 * @pre Either wifi_connect() or wifi_connect_by_wps_pbc() or wifi_connect_by_wps_pin() will invoke this callback function.
 * @see wifi_connect()
 * @see wifi_connect_by_wps_pbc()
 * @see wifi_connect_by_wps_pin()
 */
typedef void(*wifi_connected_cb)(wifi_error_e result, void *user_data);

/**
 * @brief Called after wifi_disconnect() is completed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] result  The result
 * @param[in] user_data The user data passed from wifi_disconnect()
 * @pre wifi_disconnect() will invoke this callback function.
 * @see wifi_disconnect()
 */
typedef void(*wifi_disconnected_cb)(wifi_error_e result, void *user_data);

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_MONITOR_MODULE
* @{
*/

/**
 * @brief Called when the device state is changed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] state  The device state
 * @param[in] user_data The user data passed from the callback registration function
 * @see wifi_set_device_state_changed_cb()
 * @see wifi_unset_device_state_changed_cb()
 */
typedef void(*wifi_device_state_changed_cb)(wifi_device_state_e state, void *user_data);

/**
 * @brief Called when the connection state is changed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] state  The connection state
 * @param[in] ap  The access point
 * @param[in] user_data The user data passed from the callback registration function
 * @see wifi_set_connection_state_changed_cb()
 * @see wifi_unset_connection_state_changed_cb()
 */
typedef void(*wifi_connection_state_changed_cb)(wifi_connection_state_e state, wifi_ap_h ap, void *user_data);

/**
 * @brief Called when the RSSI of connected Wi-Fi is changed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] rssi_level  The level of RSSI
 * @param[in] user_data The user data passed from the callback registration function
 * @see wifi_set_rssi_level_changed_cb()
 * @see wifi_unset_rssi_level_changed_cb()
 */
typedef void(*wifi_rssi_level_changed_cb)(wifi_rssi_level_e rssi_level, void *user_data);

/**
* @}
*/

/**
* @addtogroup CAPI_NETWORK_WIFI_CONFIG_MODULE
* @{
*/

/**
 * @brief Called when you get the found access point configurations repeatedly.
 * @since_tizen 2.4
 * @remarks @a config is valid only in this function. In order to use @a config outside this function, you must copy the config with wifi_config_clone().
 *
 * @param[in]  config		The access point configuration handle
 * @param[in]  user_data	The user data passed from the request function
 *
 * @return  @c true to continue with the next iteration of the loop, otherwise @c false to break out of the loop \n
 * @pre  wifi_config_foreach_configuration() will invoke this callback.
 * @see  wifi_config_foreach_configuration()
 */
typedef bool (*wifi_config_list_cb)(const wifi_config_h config, void *user_data);

/**
* @}
*/

/**
* @addtogroup CAPI_NETWORK_WIFI_MODULE
* @{
*/

/**
 * @brief Initializes Wi-Fi.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.get
 * @return @c 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_initialize(void);

/**
 * @brief Deinitializes Wi-Fi.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_deinitialize(void);

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_MANAGER_MODULE
* @{
*/

/**
 * @brief Activates Wi-Fi asynchronously.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.set \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] callback  The callback function to be called \n
 * 			This can be @c NULL if you don't want to get the notification.
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_SECURITY_RESTRICTED  Restricted by security system policy
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @post wifi_activated_cb() will be invoked.
 * @see wifi_activated_cb()
 * @see wifi_deactivate()
 */
int wifi_activate(wifi_activated_cb callback, void *user_data);

/**
 * @brief Activates Wi-Fi asynchronously and displays Wi-Fi picker (popup) when Wi-Fi is not automatically connected.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.set \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] callback  The callback function to be called \n
 * 			This can be @c NULL if you don't want to get the notification.
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_SECURITY_RESTRICTED  Restricted by security system policy
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @post wifi_activated_cb() will be invoked.
 * @see wifi_activated_cb()
 * @see wifi_deactivate()
 */
int wifi_activate_with_wifi_picker_tested(wifi_activated_cb callback, void *user_data);

/**
 * @brief Deactivates Wi-Fi asynchronously.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.set \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] callback  The callback function to be called \n
 *			This can be @c NULL if you don't want to get the notification.
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @post wifi_deactivated_cb() will be invoked.
 * @see wifi_deactivated_cb()
 * @see wifi_activate()
 */
int wifi_deactivate(wifi_deactivated_cb callback, void *user_data);

/**
 * @brief Checks whether Wi-Fi is activated.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.get
 * @param[out] activated  @c ture if Wi-Fi is activated,
 *			  otherwise @c false if Wi-Fi is not activated.
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_is_activated(bool* activated);

/**
 * @brief Gets the local MAC address.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks You must release @a mac_address using free().
 * @param[out] mac_address  The MAC address
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_get_mac_address(char** mac_address);

/**
 * @brief Gets the name of the network interface.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.get
 * @remarks You must release @a name using free().
 * @param[out] name  The name of network interface
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_get_network_interface_name(char** name);

/**
 * @brief Starts scan asynchronously.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.set \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] callback  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @post This function invokes wifi_scan_finished_cb().
 */
int wifi_scan(wifi_scan_finished_cb callback, void *user_data);

/**
 * @brief Starts specific ap scan, asynchronously.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.set \n
 *               %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] essid     The essid of hidden ap
 * @param[in] callback  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value.
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @post This function invokes wifi_scan_finished_cb().
 */
int wifi_scan_specific_ap(const char* essid, wifi_scan_finished_cb callback, void* user_data);

/**
 * @brief Gets the handle of the connected access point.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.get
 * @remarks You must release @a handle using wifi_ap_destroy().
 * @param[out] ap  The access point handle
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_NO_CONNECTION  There is no connected AP
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_get_connected_ap(wifi_ap_h* ap);

/**
 * @brief Gets the result of the scan.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.get
 * @param[in] callback  The callback to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @post This function invokes wifi_found_ap_cb().
 */
int wifi_foreach_found_aps(wifi_found_ap_cb callback, void *user_data);

/**
 * @brief Gets the result of specific ap scan.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.get
 * @param[in] callback  The callback to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value.
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @post This function invokes wifi_found_ap_cb().
 * @see wifi_scan_specific_ap()
 */
int wifi_foreach_found_specific_aps(wifi_found_ap_cb callback, void* user_data);

/**
 * @brief Connects the access point asynchronously.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.set \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] ap  The access point handle
 * @param[in] callback  The callback function to be called \n
 *			This can be @c NULL if you don't want to get the notification.
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @post This function invokes wifi_connected_cb().
 * @see wifi_connected_cb()
 * @see wifi_connect_by_wps_pbc()
 * @see wifi_connect_by_wps_pin()
 * @see wifi_disconnect()
 */
int wifi_connect(wifi_ap_h ap, wifi_connected_cb callback, void *user_data);

/**
 * @brief Disconnects the access point asynchronously.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.set \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] ap  The access point handle
 * @param[in] callback  The callback function to be called \n
 *			This can be @c NULL if you don't want to get the notification.
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @post This function invokes wifi_disconnected_cb().
 * @see wifi_disconnected_cb()
 * @see wifi_connect_by_wps_pbc()
 * @see wifi_connect_by_wps_pin()
 * @see wifi_connect()
 */
int wifi_disconnect(wifi_ap_h ap, wifi_disconnected_cb callback, void *user_data);

/**
 * @brief Connects the access point with WPS PBC asynchronously.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] ap  The access point handle
 * @param[in] callback  The callback function to be called \n
 *			This can be NULL if you don't want to get the notification.
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @post This function invokes wifi_connected_cb().
 * @see wifi_connected_cb()
 * @see wifi_connect()
 * @see wifi_disconnect()
 * @see wifi_ap_is_wps_supported()
 */
int wifi_connect_by_wps_pbc(wifi_ap_h ap, wifi_connected_cb callback, void *user_data);

/**
 * @brief Connects the access point with WPS PIN asynchronously.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] ap  The access point handle
 * @param[in] pin  The WPS PIN is a non-NULL string with length greater than 0 and less than or equal to 8
 * @param[in] callback  The callback function to be called (this can be NULL if you don't want to get the notification)
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @post This function invokes wifi_connected_cb().
 * @see wifi_connected_cb()
 * @see wifi_connect()
 * @see wifi_disconnect()
 * @see wifi_ap_is_wps_supported()
 */
int wifi_connect_by_wps_pin(wifi_ap_h ap, const char *pin, wifi_connected_cb callback, void *user_data);

/**
 * @brief Deletes the information of stored access point and disconnects it when it connected.
 * @details If an AP is connected, then connection information will be stored.
 * This information is used when a connection to that AP is established automatically.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile \n
* 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] ap  The access point handle
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_forget_ap(wifi_ap_h ap);

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_MONITOR_MODULE
* @{
*/

/**
 * @brief Gets the connection state.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.get
 * @param[out] connection_state  The connection state
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_get_connection_state(wifi_connection_state_e* connection_state);

/**
 * @brief Registers the callback called when the device state is changed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] callback  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER   Invalid parameter
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_set_device_state_changed_cb(wifi_device_state_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback called when the device state is changed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_unset_device_state_changed_cb(void);

/**
 * @brief Registers the callback called when the background scan is finished periodically.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] callback  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER   Invalid parameter
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_set_background_scan_cb(wifi_scan_finished_cb callback, void *user_data);

/**
 * @brief Unregisters the callback called when the scan is finished periodically.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_unset_background_scan_cb(void);

/**
 * @brief Registers the callback called when the connection state is changed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] callback  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER   Invalid parameter
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_set_connection_state_changed_cb(wifi_connection_state_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback called when the connection state is changed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_unset_connection_state_changed_cb(void);

/**
 * @brief Registers callback called when the RSSI of connected Wi-Fi is changed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] callback  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER   Invalid parameter
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_set_rssi_level_changed_cb(wifi_rssi_level_changed_cb callback, void *user_data);

/**
 * @brief Unregisters callback called when the RSSI of connected Wi-Fi is changed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_unset_rssi_level_changed_cb(void);

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_AP_MODULE
* @{
*/

/**
 * @brief Creates the access point handle.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile \n
 *            %http://tizen.org/privilege/network.get
 * @remarks You must release @a ap using wifi_ap_destroy(). \n
 *          This API needs both privileges.
 * @param[in] essid  The ESSID (Extended Service Set Identifier) should be null-terminated and can be UTF-8 encoded
 * @param[out] ap  The access point handle
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @see wifi_ap_destroy()
 */
int wifi_ap_create(const char* essid, wifi_ap_h* ap);

/**
 * @brief Creates the hidden access point handle.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks You must release @a ap using wifi_ap_destroy().
 * @param[in] essid  The ESSID (Extended Service Set Identifier) should be null-terminated and can be UTF-8 encoded
 * @param[out] ap  The access point handle
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @see wifi_ap_destroy()
 */
int wifi_ap_hidden_create(const char* essid, wifi_ap_h* ap);

/**
 * @brief Destroys the access point handle.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @see wifi_ap_create()
 */
int wifi_ap_destroy(wifi_ap_h ap);

/**
 * @brief Clones the access point handle.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks You must release @a cloned_ap using wifi_ap_destroy().
 * @param[out] cloned_ap  The cloned access point handle
 * @param[in] origin  The origin access point handle
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 * @see wifi_ap_destroy()
 */
int wifi_ap_clone(wifi_ap_h* cloned_ap, wifi_ap_h origin);

/**
 * @brief Refreshes the access point information.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.get
 * @remarks You should call this function in order to get the current access point information, because the information can be changed.
 * @param[in] ap  The access point handle
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_refresh(wifi_ap_h ap);

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_AP_NETWORK_MODULE
* @{
*/

/**
 * @brief Gets ESSID (Extended Service Set Identifier).
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks You must release @a essid using free().
 * @param[in] ap  The access point handle
 * @param[out] essid  The ESSID
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_get_essid(wifi_ap_h ap, char** essid);

/**
 * @brief Gets BSSID (Basic Service Set Identifier).
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks You must release @a bssid using free().
 * @param[in] ap  The access point handle
 * @param[out] bssid  The BSSID
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_get_bssid(wifi_ap_h ap, char** bssid);

/**
 * @brief Gets the RSSI.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] rssi  The RSSI
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_get_rssi(wifi_ap_h ap, int* rssi);

/**
 * @brief Gets the frequency band (MHz).
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] frequency  The frequency
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_get_frequency(wifi_ap_h ap, int* frequency);

/**
 * @brief Gets the max speed (Mbps).
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] max_speed  The max speed
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_get_max_speed(wifi_ap_h ap, int* max_speed);

/**
 * @brief Checks whether the access point is favorite or not.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] favorite  @c true if access point is favorite,
 *			 otherwise @c false if access point is not favorite
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_is_favorite(wifi_ap_h ap, bool* favorite);

/**
 * @brief Checks whether the access point is passpoint or not.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] passpoint  @c ture if access point is passpoint,
 *			  otherwise @c false if access point is not passpoint.
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_is_passpoint(wifi_ap_h ap, bool* passpoint);

/**
 * @brief Gets the connection state.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] state  The connection state
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_connection_state(wifi_ap_h ap, wifi_connection_state_e* state);

/**
 * @brief Gets the config type of IP.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[in] address_family  The address family
 * @param[out] type  The type of IP config
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_ip_config_type(wifi_ap_h ap, wifi_address_family_e address_family, wifi_ip_config_type_e* type);

/**
 * @brief Sets the config type of IP.
 * @details If you set IP config type to #WIFI_IP_CONFIG_TYPE_STATIC,
 * then IP address, Gateway and Subnet mask will be set to the initial value "0.0.0.0".
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile \n
 *	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] ap  The access point handle
 * @param[in] address_family  The address family
 * @param[in] type  The type of IP config
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_ip_config_type(wifi_ap_h ap, wifi_address_family_e address_family, wifi_ip_config_type_e type);

/**
 * @brief Gets the IP address.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks You must release @a ip_address using free().
 * @param[in] ap  The access point handle
 * @param[in] address_family  The address family
 * @param[out] ip_address  The IP address
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_ip_address(wifi_ap_h ap, wifi_address_family_e address_family, char** ip_address);

/**
 * @brief Sets the IP address.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] ap  The access point handle
 * @param[in] address_family  The address family
 * @param[in] ip_address  The IP address; if you set this value to NULL, then the existing value will be deleted
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_ip_address(wifi_ap_h ap, wifi_address_family_e address_family, const char* ip_address);

/**
 * @brief Gets the subnet mask.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks You must release @a subnet_mask using free().
 * @param[in] ap  The access point handle
 * @param[in] address_family  The address family
 * @param[out] subnet_mask  The subnet mask
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_subnet_mask(wifi_ap_h ap, wifi_address_family_e address_family, char** subnet_mask);

/**
 * @brief Sets the subnet mask.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] ap  The access point handle
 * @param[in] address_family  The address family
 * @param[in] subnet_mask  The subnet mask; if you set this value to NULL, then the existing value will be deleted
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_subnet_mask(wifi_ap_h ap, wifi_address_family_e address_family, const char* subnet_mask);

/**
 * @brief Gets the gateway address.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks You must release @a gateway_address using free().
 * @param[in] ap  The access point handle
 * @param[in] address_family  The address family
 * @param[out] gateway_address  The gateway address
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_gateway_address(wifi_ap_h ap, wifi_address_family_e address_family, char** gateway_address);

/**
 * @brief Sets the gateway address.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] ap  The access point handle
 * @param[in] address_family  The address family
 * @param[in] gateway_address  The gateway address \n
 *			       If you set this value to @c NULL, then the existing value will be deleted.
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_gateway_address(wifi_ap_h ap, wifi_address_family_e address_family, const char* gateway_address);

/**
 * @brief Gets the proxy address.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks You must release @a proxy_address using free().
 * @param[in] ap  The access point handle
 * @param[in] address_family  The address family
 * @param[out] proxy_address  The proxy address
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_proxy_address(wifi_ap_h ap, wifi_address_family_e address_family, char** proxy_address);

/**
 * @brief Sets the proxy address.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] ap  The access point handle
 * @param[in] address_family  The address family
 * @param[in] proxy_address  The proxy address \n
 *			     If you set this value to @c NULL, then the existing value will be deleted.
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_proxy_address(wifi_ap_h ap, wifi_address_family_e address_family, const char* proxy_address);

/**
 * @brief Gets the Proxy type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] type  The type of proxy
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_proxy_type(wifi_ap_h ap, wifi_proxy_type_e* type);

/**
 * @brief Sets the Proxy address.
 * @details If you set Proxy type to #WIFI_PROXY_TYPE_AUTO or #WIFI_PROXY_TYPE_MANUAL, then Proxy will be restored.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile \n
 * 	      %http://tizen.org/privilege/network.get
 * @remark This API needs both privileges.
 * @param[in] ap  The access point handle
 * @param[in] proxy_type  The type of proxy
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_proxy_type(wifi_ap_h ap, wifi_proxy_type_e proxy_type);

/**
 * @brief Gets the DNS address.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks The allowance of DNS address is @c 2.You must release @a dns_address using free().
 * @param[in] ap  The access point handle
 * @param[in] order  The order of DNS address; it starts from 1, which means first DNS address
 * @param[in] address_family  The address family
 * @param[out] dns_address  The DNS address
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_dns_address(wifi_ap_h ap, int order, wifi_address_family_e address_family, char** dns_address);

/**
 * @brief Sets the DNS address.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile \n
 * 	      %http://tizen.org/privilege/network.get
 * @remarks The allowance of DNS address is @c 2 \n
 *	    This API needs both privileges.
 * @param[in] ap  The access point handle
 * @param[in] order  The order of DNS address \n
 *		     It starts from @c 1, which means first DNS address.
 * @param[in] address_family  The address family
 * @param[in] dns_address  The DNS address \n
 *			   If you set this value to @c NULL, then the existing value will be deleted.
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED  Address family not supported
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_dns_address(wifi_ap_h ap, int order, wifi_address_family_e address_family, const char* dns_address);

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_AP_SECURITY_MODULE
* @{
*/

/**
 * @brief Gets the Wi-Fi security mode.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] type  The type of Wi-Fi security
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_security_type(wifi_ap_h ap, wifi_security_type_e* type);

/**
 * @brief Sets the Wi-Fi security mode.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[in] type  The type of Wi-Fi security
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_security_type(wifi_ap_h ap, wifi_security_type_e type);

/**
 * @brief Gets the Wi-Fi encryption type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] type  The type of Wi-Fi encryption
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_encryption_type(wifi_ap_h ap, wifi_encryption_type_e* type);

/**
 * @brief Sets the Wi-Fi encryption type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[in] type  The type of Wi-Fi encryption
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_encryption_type(wifi_ap_h ap, wifi_encryption_type_e type);

/**
 * @brief Checks whether the passphrase is required or not.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks This function is not valid if security type is #WIFI_SECURITY_TYPE_EAP.
 * @param[in] ap  The access point handle
 * @param[out] required  @c true if passphrase is required,
 *			 @c false if passphrase is not required.
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_is_passphrase_required(wifi_ap_h ap, bool* required);

/**
 * @brief Sets the passphrase.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[in] passphrase  The passphrase of access point
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_passphrase(wifi_ap_h ap, const char* passphrase);

/**
 * @brief Checks whether the WPS(Wi-Fi Protected Setup) is supported or not.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] supported  @c ture if WPS is supported,
 *			  otherwise @c false is WPS is not supported.
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 * @see wifi_connect_by_wps_pbc()
 * @see wifi_connect_by_wps_pin()
 */
int wifi_ap_is_wps_supported(wifi_ap_h ap, bool* supported);

/**
* @}
*/


/**
* @addtogroup CAPI_NETWORK_WIFI_AP_SECURITY_EAP_MODULE
* @{
*/

/**
 * @brief Sets the passphrase of EAP.
 * @details You can set one of @a user_name and @a password as @c NULL.
 * In this case, the value of a parameter which is set as @c NULL will be the previous value.
 * But it is not allowed that both @a user_name and @a password are set as @c NULL.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks This function is valid only if the EAP type is #WIFI_EAP_TYPE_PEAP or #WIFI_EAP_TYPE_TTLS.
 * @param[in] ap  The access point handle
 * @param[in] user_name  The user name \n
 *			 This value can be @c NULL.
 * @param[in] password  The password \n
 *			This value can be @c NULL.
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_eap_passphrase(wifi_ap_h ap, const char* user_name, const char* password);

/**
 * @brief Gets the passphrase of EAP.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks This function is valid only if the EAP type is #WIFI_EAP_TYPE_PEAP or #WIFI_EAP_TYPE_TTLS.
 * 	    You must release @a user_name using free().
 * @param[in] ap  The access point handle
 * @param[out] user_name  The user name
 * @param[out] is_password_set  @c ture if password is set,
 *				otherwise @c flase if password is not set.
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_eap_passphrase(wifi_ap_h ap, char** user_name, bool* is_password_set);

/**
 * @brief Gets the CA Certificate of EAP.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks This function is valid only if the EAP type is #WIFI_EAP_TYPE_TLS.
 * 	    You must release @a file using free().
 * @param[in] ap  The access point handle
 * @param[out] file  The file path of CA Certificate
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_eap_ca_cert_file(wifi_ap_h ap, char** file);

/**
 * @brief Sets the CA Certificate of EAP.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks This function is valid only if the EAP type is #WIFI_EAP_TYPE_TLS.
 * @param[in] ap  The access point handle
 * @param[in] file  The file path of CA Certificate
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_eap_ca_cert_file(wifi_ap_h ap, const char* file);

/**
 * @brief Gets the Client Certificate of EAP.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks This function is valid only if the EAP type is #WIFI_EAP_TYPE_TLS.
 * 	    You must release @a file using free().
 * @param[in] ap  The access point handle
 * @param[out] file  The file path of Client Certificate
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_eap_client_cert_file(wifi_ap_h ap, char** file);

/**
 * @brief Sets the CA Certificate of EAP.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks This function is valid only if the EAP type is #WIFI_EAP_TYPE_TLS.
 * @param[in] ap  The access point handle
 * @param[in] file  The file path of Client Certificate
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_eap_client_cert_file(wifi_ap_h ap, const char* file);

/**
 * @brief Gets the private key file of EAP.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks This function is valid only if the EAP type is #WIFI_EAP_TYPE_TLS.
 * 	    You must release @a file using free().
 * @param[in] ap  The access point handle
 * @param[out] file  The file path of private key
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_eap_private_key_file(wifi_ap_h ap, char** file);

/**
 * @brief Sets the private key information of EAP.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks This function is valid only if the EAP type is #WIFI_EAP_TYPE_TLS.
 * @param[in] ap  The access point handle
 * @param[in] file  The file path of private key
 * @param[in] password  The password
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_eap_private_key_info(wifi_ap_h ap, const char* file, const char* password);

/**
 * @brief Gets the EAP type of Wi-Fi.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] type  The type of EAP
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_eap_type(wifi_ap_h ap, wifi_eap_type_e* type);

/**
 * @brief Sets the EAP type of Wi-Fi.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[in] type  The type of EAP
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_eap_type(wifi_ap_h ap, wifi_eap_type_e type);

/**
 * @brief Gets the type of EAP phase2 authentication of Wi-Fi.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[out] type  The type of EAP phase2 authentication
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_eap_auth_type(wifi_ap_h ap, wifi_eap_auth_type_e* type);

/**
 * @brief Sets the type of EAP phase2 authentication of Wi-Fi.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @param[in] ap  The access point handle
 * @param[in] type  The type of EAP phase2 authentication
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_set_eap_auth_type(wifi_ap_h ap, wifi_eap_auth_type_e type);

/**
* @}
*/

/**
* @addtogroup CAPI_NETWORK_WIFI_CONFIG_MODULE
* @{
*/

/**
 * @brief Gets access point configuration handle.
 * @since_tizen 2.4
 * @remarks You must release @a config using wifi_config_destroy().
 *
 * @param[in] name				The access point name
 * @param[in] passphrase		The access point passphrase
 * @param[in] security_type		The access point security type
 * @param[out] config			The access point configuration handle
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION	Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY		Out of memory
 * @retval #WIFI_ERROR_NOT_SUPPORTED		Not supported
 * @see wifi_config_destroy()
 * @pre This API needs wifi_initialize() before use
 */
int wifi_config_create(const char *name, const char *passphrase, wifi_security_type_e security_type, wifi_config_h *config);

/**
 * @brief Clones the access point configuration handle.
 * @since_tizen 2.4
 * @remarks You must release @a cloned_config using wifi_config_destroy().
 *
 * @param[in] origin				The origin access point configuration handle
 * @param[out] cloned_config	The cloned access point configuration handle
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION	Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY		Out of memory
 * @retval #WIFI_ERROR_NOT_SUPPORTED		Not supported
 * @see wifi_config_destroy()
 */
int wifi_config_clone(wifi_config_h origin, wifi_config_h *cloned_config);

/**
 * @brief Destroys the access point configuration handle.
 * @since_tizen 2.4
 *
 * @param[in] config	The access point configuration handle
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION	Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_NOT_SUPPORTED		Not supported
 * @see wifi_config_create()
 * @see wifi_config_clone()
 */
int wifi_config_destroy(wifi_config_h config);

/**
 * @brief Saves Wi-Fi configuration of access point.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile
 *
 * @param[in] config	The access point configuration handle
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION	Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED	Permission denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED		Not supported
 * @see wifi_config_create()
 */
int wifi_config_save_configuration(wifi_config_h config);

/**
 * @brief Gets the result of access point configurations repeatedly.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile
 *
 * @param[in] callback		The callback to be called
 * @param[in] user_data		The user data passed to the callback function
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION	Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED	Permission denied
 * @retval #WIFI_ERROR_OUT_OF_MEMORY		Out of memory
 * @retval #WIFI_ERROR_NOT_SUPPORTED		Not supported
 * @pre This API needs wifi_initialize() before use.
 * @post This function invokes wifi_config_list_cb().
 */
int wifi_config_foreach_configuration(wifi_config_list_cb callback, void *user_data);

/**
 * @brief Gets the name of access point from configuration.
 * @since_tizen 2.4
 * @remarks You must release @a name using free().
 *
 * @param[in] config	The access point configuration handle
 * @param[out] name		The name of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION	Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY		Out of memory
 * @retval #WIFI_ERROR_NOT_SUPPORTED		Not supported
 */
int wifi_config_get_name(wifi_config_h config, char **name);

/**
 * @brief Gets the security type of access point from configuration.
 * @since_tizen 2.4
 *
 * @param[in] config			The access point configuration handle
 * @param[out] security_type	The security type of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION	Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_NOT_SUPPORTED		Not supported
 */
int wifi_config_get_security_type(wifi_config_h config, wifi_security_type_e *security_type);

/**
 * @brief Sets access point proxy address configuration.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile
 *
 * @param[in] config			The access point configuration handle
 * @param[in] address_family	The address family
 * @param[in] proxy_address		The proxy address
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION	Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED	Permission denied
 * @retval #WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED Not supported address family
 * @retval #WIFI_ERROR_NOT_SUPPORTED		Not supported
 */
int wifi_config_set_proxy_address(wifi_config_h config, wifi_address_family_e address_family, const char *proxy_address);

/**
 * @brief Gets the proxy address of access point from configuration.
 * @since_tizen 2.4
 * @remarks You must release @a proxy_address using free().
 *
 * @param[in] config			The access point configuration handle
 * @param[out] address_family	The address family
 * @param[out] proxy_address	The proxy address
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION	Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_OUT_OF_MEMORY		Out of memory
 * @retval #WIFI_ERROR_NOT_SUPPORTED		Not supported
 */
int wifi_config_get_proxy_address(wifi_config_h config, wifi_address_family_e *address_family, char **proxy_address);

/**
 * @brief Sets the hidden property of access point from the configuration.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile
 *
 * @param[in] config		The access point configuration handle
 * @param[in] is_hidden		true to enable and false to disable
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION	Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED	Permission denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED		Not supported
 */
int wifi_config_set_hidden_ap_property(wifi_config_h config, bool is_hidden);

/**
 * @brief Gets the hidden property of access point from the configuration.
 * @since_tizen 2.4
 *
 * @param[in] config		The access point configuration handle
 * @param[out] is_hidden	The hidden property of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION	Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_NOT_SUPPORTED		Not supported
 */
int wifi_config_get_hidden_ap_property(wifi_config_h config, bool *is_hidden);

/**
 * @brief Gets access point anonymous identity from configuration.
 * @since_tizen 2.4
 * @remarks You must release @a anonymous_identity using free().
 *
 * @param[in] config				The access point configuration handle
 * @param[out] anonymous_identity	The anonymous identity of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 */
int wifi_config_get_eap_anonymous_identity(wifi_config_h config, char** anonymous_identity);

/**
 * @brief Sets access point anonymous identity to configuration.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile
 *
 * @param[in] config				The access point configuration handle
 * @param[in] anonymous_identity	The anonymous identity
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED	Permission Denied
 */
int wifi_config_set_eap_anonymous_identity(wifi_config_h config, const char* anonymous_identity);

/**
 * @brief Gets access point cacert file from configuration.
 * @since_tizen 2.4
 * @remarks You must release @a ca_cert using free().
 * @remarks The mediastorage privilege http://tizen.org/privilege/mediastorage is needed \n
 * 			 if @a image_path is relevant to media storage.\n
 * 			 The externalstorage privilege http://tizen.org/privilege/externalstorage is needed \n
 * 			 if @a image_path is relevant to external storage.
 *
 * @param[in] config		The access point configuration handle
 * @param[out] ca_cert		The certification authority(CA) certificates file of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 */
int wifi_config_get_eap_ca_cert_file(wifi_config_h config, char** ca_cert);

/**
 * @brief Sets access point cacert file to configuration.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile
 * @remarks The mediastorage privilege http://tizen.org/privilege/mediastorage is needed \n
 * 			 if @a image_path is relevant to media storage.\n
 * 			 The externalstorage privilege http://tizen.org/privilege/externalstorage is needed \n
 * 			 if @a image_path is relevant to external storage.
 *
 * @param[in] config		The access point configuration handle
 * @param[in] ca_cert		The certification authority(CA) certificates file of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED	Permission Denied
 */
int wifi_config_set_eap_ca_cert_file(wifi_config_h config, const char* ca_cert);

/**
 * @brief Gets access point client cert file from configuration.
 * @since_tizen 2.4
 * @remarks You must release @a client_crt using free().
 *
 * @param[in] config		The access point configuration handle
 * @param[out] client_crt	The certification authority(CA) certificates file of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 */
int wifi_config_get_eap_client_cert_file(wifi_config_h config, char** client_cert);

/**
 * @brief Sets access point client cert file to configuration.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile
 *
 * @param[in] config		The access point configuration handle
 * @param[in] private_key	The private key file
 * @param[in] client_crt		The certification authority(CA) certificates file of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED	Permission Denied
 */
int wifi_config_set_eap_client_cert_file(wifi_config_h config, const char* private_key, const char* client_cert);

/**
 * @brief Gets access point identity from configuration.
 * @since_tizen 2.4
 * @remarks You must release @a identity using free().
 *
 * @param[in] config		The access point configuration handle
 * @param[out] identity		The identity of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 */
int wifi_config_get_eap_identity(wifi_config_h config, char** identity);

/**
 * @brief Sets access point identity to configuration.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile
 *
 * @param[in] config		The access point configuration handle
 * @param[in] identity		The identity
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED	Permission Denied
 */
int wifi_config_set_eap_identity(wifi_config_h config, const char* identity);

/**
 * @brief Gets access point eap type from configuration.
 * @since_tizen 2.4
 *
 * @param[in] config		The access point configuration handle
 * @param[out] eap_type	The eap type of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 */
int wifi_config_get_eap_type(wifi_config_h config, wifi_eap_type_e *eap_type);

/**
 * @brief Sets access point eap type to configuration.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile
 *
 * @param[in] config		The access point configuration handle
 * @param[in] eap_type		The eap type
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED	Permission Denied
 */
int wifi_config_set_eap_type(wifi_config_h config, wifi_eap_type_e eap_type);

/**
 * @brief Gets access point eap auth type from configuration.
 * @since_tizen 2.4
 *
 * @param[in] config			The access point configuration handle
 * @param[out] eap_auth_type	The eap auth type of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 */
int wifi_config_get_eap_auth_type(wifi_config_h config, wifi_eap_auth_type_e* eap_auth_type);

/**
 * @brief Sets access point eap auth type to configuration.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile
 *
 * @param[in] config			The access point configuration handle
 * @param[in] eap_auth_type	The eap auth type
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED	Permission Denied
 */
int wifi_config_set_eap_auth_type(wifi_config_h config, wifi_eap_auth_type_e eap_auth_type);

/**
 * @brief Gets access point subject match from configuration.
 * @since_tizen 2.4
 * @remarks You must release @a subject_match using free().
 *
 * @param[in] config			The access point configuration handle
 * @param[out] subject_match	The subject match of access point
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 */
int wifi_config_get_eap_subject_match(wifi_config_h config, char** subject_match);

/**
 * @brief Sets access point subject match to configuration.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.profile
 *
 * @param[in] config			The access point configuration handle
 * @param[in] subject_match	The subject match
 *
 * @return 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE					Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED	Permission Denied
 */
int wifi_config_set_eap_subject_match(wifi_config_h config, const char* subject_match);

/**
 * @}
 */

/**
 * @addtogroup CAPI_NETWORK_WIFI_TDLS
 * @{
 */

/**
 * @brief Enumeration for the state of the Wi-Fi TDLS.
 * @since_tizen 3.0
 */
typedef enum
{
	WIFI_TDLS_STATE_DISCONNECTED = 0,  /**< Wi-Fi TDLS is Disconnected */
	WIFI_TDLS_STATE_CONNECTED = 1,     /**< Wi-Fi TDLS is Connected */
} wifi_tdls_state_e;

/**
 * @brief Called when the WiFi TDLS state is changed.
 * @since_tizen 3.0
 *
 * @param[in] state  The TDLS state
 * @param[in] peer_mac_addr  MAC address of the TDLS peer
 * @param[in] user_data  The user data passed from the callback registration function
 * @see wifi_tdls_set_state_changed_cb()
 * @see wifi_tdls_unset_state_changed_cb()
 */
typedef void(*wifi_tdls_state_changed_cb)(wifi_tdls_state_e state, char* peer_mac_addr, void* user_data);

/**
 * @brief Disconnects the connected peer.
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.set
 *
 * @param[in] ap  The MAC address of the connected peer
 *
 * @return @c 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED     Not supported
 */
int wifi_tdls_disconnect(const char* peer_mac_addr);

/**
 * @brief Gets Peer Mac address of Connected peer.
 * @since_tizen 3.0
 * @privlevel public
 * @privilege %http://tizen.org/privilege/network.get
 *
 * @remarks The @a peer_mac_addr should be freed using free().
 * @param[out] peer_mac_addr  The MAC address of the connected peer
 *
 * @return @c 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NO_CONNECTION     No active TDLS Connection
 * @retval #WIFI_ERROR_NOT_SUPPORTED     Not supported
 */
int wifi_tdls_get_connected_peer(char** peer_mac_addr);

/**
 * @brief Registers the callback called when TDLS state is changed.
 * @since_tizen 3.0
 *
 * @param[in] callback  The callback function to be called
 * @param[in] user_data The user data passed to the callback function
 *
 * @return @c 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_INVALID_PARAMETER   Invalid parameter
 * @retval #WIFI_ERROR_NOT_SUPPORTED     Not supported
 */
int wifi_tdls_set_state_changed_cb(wifi_tdls_state_changed_cb callback, void* user_data);

/**
 * @brief Unregisters the callback called when TDLS state is changed.
 * @since_tizen 3.0
 *
 * @return @c 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_NOT_SUPPORTED     Not supported
 */
int wifi_tdls_unset_state_changed_cb(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_NETWORK_WIFI_H__ */
