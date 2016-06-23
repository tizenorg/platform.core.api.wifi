/*
 * Copyright (c) 2012-2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef __TIZEN_NETWORK_WIFI_EXTENSION_H__
#define __TIZEN_NETWORK_WIFI_EXTENSION_H__

#include <tizen.h>
#include "wifi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file wifi_extension.h
 */

/**
* @brief DNS Configuration type
* @since_tizen @if TV 3.0 @endif
*/
typedef enum
{
    WIFI_DNS_CONFIG_TYPE_NONE = 0,  /**< Not defined */
    WIFI_DNS_CONFIG_TYPE_STATIC  = 1,  /**< Manual DNS configuration */
    WIFI_DNS_CONFIG_TYPE_DYNAMIC = 2,  /**< Config DNS using DHCP client*/
} wifi_dns_config_type_e;

/**
 * @brief Enumeration for WiFi Disconnect reason.
 * @since_tizen @if TV 3.0 @endif
 */
typedef enum
{
	WIFI_REASON_UNSPECIFIED = 1,			/**< Unspecified reason */
	WIFI_REASON_PREV_AUTH_NOT_VALID = 2,		/**< Previous authentication no longer valid */
	WIFI_REASON_DEAUTH_LEAVING = 3,			/**< Deauthenticated because sending STA is leaving (or has left) IBSS or ESS */
	WIFI_REASON_DISASSOC_DUE_TO_INACTIVITY = 4,	/**< Disassociated due to inactivity */
	WIFI_REASON_DISASSOC_AP_BUSY = 5,		/**< Disassociated because AP is unable to handle all currently associated STAs*/
	WIFI_REASON_CLASS2_FRAME_FROM_NONAUTH_STA = 6,  /**< Class 2 frame received from nonauthenticated STA*/
	WIFI_REASON_CLASS3_FRAME_FROM_NONASSOC_STA = 7, /**< Class 3 frame received from nonassociated STA*/
	WIFI_REASON_DISASSOC_STA_HAS_LEFT = 8,		/**< Disassociated because sending STA is leaving (or has left) BSS*/
	WIFI_REASON_STA_REQ_ASSOC_WITHOUT_AUTH = 9,	/**< STA requesting (re)association is not authenticated with responding STA */
	WIFI_REASON_PWR_CAPABILITY_NOT_VALID = 10,	/**< Disassociated because the inform ation in the Power Capability element is unacceptable */
	WIFI_REASON_SUPPORTED_CHANNEL_NOT_VALID = 11,	/**< Disassociated because the information in the Supported Channels element is unacceptable */
	WIFI_REASON_INVALID_IE = 13,			/**< Invalid element i.e., an element defined in this standard for which the content does not meet  the specifications in Clause 8 */
	WIFI_REASON_MICHAEL_MIC_FAILURE = 14,		/**< Message integrity code (MIC) failure */
	WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT = 15,	/**< 4-Way Handshake timeout */
	WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT = 16,	/**< Group Key Handshake timeout */
	WIFI_REASON_IE_IN_4WAY_DIFFERS = 17,		/**<  element in 4-Way Handshake different from (Re)Association Request/Probe Response/Beacon frame*/
	WIFI_REASON_GROUP_CIPHER_NOT_VALID = 18,	/**< Invalid group cipher */
	WIFI_REASON_PAIRWISE_CIPHER_NOT_VALID = 19,	/**< Invalid pairwise cipher */
	WIFI_REASON_AKMP_NOT_VALID = 20,		/**< Invalid AKMP */
	WIFI_REASON_UNSUPPORTED_RSN_IE_VERSION = 21,	/**< Unsupported RSNE version */
	WIFI_REASON_INVALID_RSN_IE_CAPAB = 22,		/**< Invalid RSNE capabilities */
	WIFI_REASON_IEEE_802_1X_AUTH_FAILED = 23,	/**< IEEE 802.1X authentication failed */
	WIFI_REASON_CIPHER_SUITE_REJECTED = 24,		/**< Cipher suite rejected because of the security policy */
	WIFI_REASON_TDLS_TEARDOWN_UNREACHABLE = 25,	/**< TDLS direct-link teardown due to TDLS peer STA unreachable via the TDLS direct link */
	WIFI_REASON_TDLS_TEARDOWN_UNSPECIFIED = 26,	/**< TDLS direct-link teardown  for unspecified reason */
	WIFI_REASON_DISASSOC_LOW_ACK = 34,		/**< Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions */
	WIFI_REASON_MESH_PEERING_CANCELLED = 52,	/**< SME cancels the mesh peering instance with the reason other than reaching the maximum number of peer mesh STAs */
	WIFI_REASON_MESH_MAX_PEERS = 53,		/**< The mesh STA has reached the supported maximum number of peer mesh STAs */
	WIFI_REASON_MESH_CONFIG_POLICY_VIOLATION = 54,  /**< The received information violates the Mesh Configuration policy configured in the mesh STA profile */
	WIFI_REASON_MESH_CLOSE_RCVD = 55,		/**< The mesh STA has received a Mesh Peering Close message requesting to close the mesh peering */
	WIFI_REASON_MESH_MAX_RETRIES = 56,		/**< The mesh STA has resent dot11MeshMaxRetries Mesh Peering Open messages, without receiving a Mesh Peering Confirm message */
	WIFI_REASON_MESH_CONFIRM_TIMEOUT = 57,		/**< The confirmTimer for the mesh peering instance times out. */
	WIFI_REASON_MESH_INVALID_GTK = 58,		/**< The mesh STA fails to unwrap the GTK or the values in the wrapped contents do not match */
	WIFI_REASON_MESH_INCONSISTENT_PARAMS = 59,	/**< The mesh STA receives inconsistent information about the mesh parameters between Mesh Peering Management frames */
	WIFI_REASON_MESH_INVALID_SECURITY_CAP = 60,	/**< The mesh STA does not have proxy information for this external destination */
} wifi_disconnect_reason_e;

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_WIFI_MANAGER_MODULE
 * @{
 */

/**
 * @brief Connects the access point with WPS PBC without enterning ssid.
 * @since_tizen @if TV 3.0 @endif
 * @param[in] callback  The callback function to be called \n
 *			This can be NULL if you don't want to get the notification.
 * @param[in] user_data The user data passed to the callback function
 * @return @c 0 on success, otherwise negative error value
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
int wifi_connect_by_wps_pbc_without_ssid(wifi_connected_cb callback,
					 void *user_data);

/**
 * @brief Connects the access point with WPS PIN without enterning ssid.
 * @since_tizen @if TV 3.0 @endif
 * @param[in] callback  The callback function to be called \n
 *			This can be NULL if you don't want to get the notification.
 * @param[in] user_data The user data passed to the callback function
 * @return @c 0 on success, otherwise negative error value
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
 int wifi_connect_by_wps_pin_without_ssid(const char* pin,
					  wifi_connected_cb callback,
					  void* user_data);

/**
 * @brief Stops ongoing WPS Provisioning / disconnects connected access point.
 * @since_tizen @if TV 3.0 @endif
 * @return @c 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_INVALID_OPERATION  Invalid operation
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
*/
int wifi_cancel_wps(void);

/**
 * @}
 */

/**
  * @addtogroup CAPI_NETWORK_WIFI_AP_MODULE
  * @{
  */

/**
 * @brief Sets the IPV6 prefix length.
 * @since_tizen @if TV 3.0 @endif
 * @param[in] ap  The handle of access point
 * @param[in] prefix_len  The prefix length
 * @return @c 0 on success, otherwise negative error value.
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_set_prefix_length(wifi_ap_h ap, unsigned char prefix_len);

/**
 * @brief Gets the IPv6 prefix length.
 * @since_tizen @if TV 3.0 @endif
 * @param[in] ap  The handle of access point
 * @param[out] prefix_len The prefix length.
 * @return @c 0 on success, otherwise negative error value.
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_get_prefix_length(wifi_ap_h ap, unsigned char* prefix_len);

/**
 * @brief Sets the DNS config type.
 * @since_tizen @if TV 3.0 @endif
 * @param[in] ap  The handle of access point
 * @param[in] address_family  The address family
 * @param[in] type  The type of DNS config
 * @return @c 0 on success, otherwise negative error value.
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_set_dns_config_type(wifi_ap_h ap,
				wifi_address_family_e address_family,
				wifi_dns_config_type_e type);

/**
 * @brief Gets the DNS config type.
 * @since_tizen @if TV 3.0 @endif
 * @param[in] ap  The handle of access point
 * @param[in] address_family  The address family
 * @param[out] type  The type of DNS config
 * @return @c 0 on success, otherwise negative error value.
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED	Not supported
 */
int wifi_ap_get_dns_config_type(wifi_ap_h ap,
				wifi_address_family_e address_family,
				wifi_dns_config_type_e* type);

/**
 * @brief Gets the Disconnect Reason of AP.
 * @since_tizen @if TV 3.0 @endif
 * @remarks This function provides valid information only when AP gets disconnected after connection.
 * @param[in] ap  The access point handle
 * @param[out] disconnect_reason  The disconnect reason of AP of type wifi_disconnect_reason_e
 * @return @c 0 on success, otherwise negative error value
 * @retval #WIFI_ERROR_NONE  Successful
 * @retval #WIFI_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval #WIFI_ERROR_PERMISSION_DENIED Permission Denied
 * @retval #WIFI_ERROR_OPERATION_FAILED  Operation failed
 * @retval #WIFI_ERROR_NOT_SUPPORTED   Not supported
 */
int wifi_ap_get_disconnect_reason(wifi_ap_h ap,
				  wifi_disconnect_reason_e* disconnect_reason);
/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_NETWORK_WIFI_EXTENSION_H__ */

