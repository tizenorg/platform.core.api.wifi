/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __TIZEN_NETWORK_WIFI_DOC_H__
#define __TIZEN_NETWORK_WIFI_DOC_H__

/**
 * @defgroup CAPI_NETWORK_WIFI_MODULE  Wi-Fi
 * @brief The Wi-Fi API provides functions for managing Wi-Fi and monitoring the state of Wi-Fi.
 * @ingroup CAPI_NETWORK_FRAMEWORK
 *
 * @section CAPI_NETWORK_WIFI_MODULE_HEADER Required Header
 *   \#include <wifi.h>
 *
 * @section CAPI_NETWORK_WIFI_MODULE_OVERVIEW Overview
 * Wi-Fi allows your application to connect to a Wireless Local Area Network (WLAN) and to transfer data over the network.
 * The Wi-Fi Manager enables your application to activate and deactivate a local Wi-Fi device, and to connect to a WLAN network
 * in the infrastructure mode.
 * @section CAPI_NETWORK_WIFI_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.wifi\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 *
 */

/**
 * @defgroup CAPI_NETWORK_WIFI_MANAGER_MODULE  Wi-Fi Manager
 * @brief The Wi-Fi API provides functions for managing Wi-Fi.
 * @ingroup CAPI_NETWORK_WIFI_MODULE
 *
 * @section CAPI_NETWORK_WIFI_MANAGER_MODULE_HEADER Required Header
 *   \#include <wifi.h>
 *
 * @section CAPI_NETWORK_WIFI_MANAGER_MODULE_OVERVEW Overview
 * The Wi-Fi Manager provides functions for managing Wi-Fi.
 * Using the Wi-Fi Manager, you can implement features that allow the users of your application to:
 * - Activate / Deactivate the Wi-Fi device
 * - Connect to the access point
 * - Scans the access points
 * @section CAPI_NETWORK_WIFI_MANAGER_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.wifi\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 *
 */

/**
 * @defgroup CAPI_NETWORK_WIFI_MONITOR_MODULE  Wi-Fi Monitor
 * @brief The Wi-Fi API provides functions for monitoring the state of Wi-Fi.
 * @ingroup CAPI_NETWORK_WIFI_MODULE
 *
 * @section CAPI_NETWORK_WIFI_MONITOR_MODULE_HEADER Required Header
 *   \#include <wifi.h>
 *
 * @section CAPI_NETWORK_WIFI_MONITOR_MODULE_OVERVIEW Overview
 * The Wi-Fi Monitor allows monitoring the changes of Wi-Fi.
 * @section CAPI_NETWORK_WIFI_MONITOR_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.wifi\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 *
 */

/**
 * @defgroup CAPI_NETWORK_WIFI_AP_MODULE  AP
 * @brief The Access Point API provides functions for managing the Access Point.
 * @ingroup CAPI_NETWORK_WIFI_MANAGER_MODULE
 *
 * @section CAPI_NETWORK_WIFI_AP_MODULE  Required Header
 *   \#include <wifi.h>
 *
 * @section CAPI_NETWORK_WIFI_AP_MODULE_OVERVIEW Overview
 * The Access Point API provides functions for managing the Access Point. You need to create the @a ap handle for using the functions.
 * You can use Wi-Fi information with the handle.
 * @section CAPI_NETWORK_WIFI_AP_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.wifi\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 *
 */

/**
 * @defgroup CAPI_NETWORK_WIFI_AP_NETWORK_MODULE  Network Information
 * @brief The Connection Information API provides functions for managing the network information.
 * @ingroup CAPI_NETWORK_WIFI_AP_MODULE
 *
 * @section CAPI_NETWORK_WIFI_AP_CONNECTION_MODULE  Required Header
 *   \#include <wifi.h>
 *
 * @section CAPI_NETWORK_WIFI_AP_CONNECTION_MODULE_OVERVIEW Overview
 * The Connection Information API provides functions for managing the network information. You can manage the network information using the functions.
 * @section CAPI_NETWORK_WIFI_AP_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.wifi\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 *
 */

/**
 * @defgroup CAPI_NETWORK_WIFI_AP_SECURITY_MODULE  Security Information
 * @brief The Security Information API provides functions for managing the Security information.
 * @ingroup CAPI_NETWORK_WIFI_AP_MODULE
 *
 * @section CAPI_NETWORK_WIFI_AP_SECURITY_MODULE  Required Header
 *   \#include <wifi.h>
 *
 * @section CAPI_NETWORK_WIFI_AP_SECURITY_MODULE_OVERVIEW Overview
 * The Security Information API provides functions for managing the Security information. You can manage the Security information using the functions.
 * @section CAPI_NETWORK_WIFI_AP_SECURITY_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.wifi\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 *
 */

/**
 * @defgroup CAPI_NETWORK_WIFI_AP_SECURITY_EAP_MODULE  EAP
 * @brief The EAP API provides functions for managing the EAP information.
 * @ingroup CAPI_NETWORK_WIFI_AP_SECURITY_MODULE
 *
 * @section CAPI_NETWORK_WIFI_AP_SECURITY_EAP_MODULE  Required Header
 *   \#include <wifi.h>
 *
 * @section CAPI_NETWORK_WIFI_AP_SECURITY_EAP_MODULE_OVERVIEW Overview
 * The EAP API provides functions for managing the EAP information. You can manage the EAP information using the functions.
 * @section CAPI_NETWORK_WIFI_AP_SECURITY_EAP_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.wifi\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 *
 */


/**
 * @defgroup CAPI_NETWORK_WIFI_CONFIG_MODULE  Wi-Fi Configuration
 * @brief The Configuration API provides functions for managing the configuration of Wi-Fi.
 * @ingroup CAPI_NETWORK_WIFI_MODULE
 *
 * @section CAPI_NETWORK_WIFI_CONFIG_MODULE  Required Header
 *   \#include <wifi.h>
 *
 * @section CAPI_NETWORK_WIFI_CONFIG_MODULE_OVERVIEW Overview
 * The Configuration API provides functions for managing the configuration of Wi-Fi. You can manage the configuration information using the functions.
 * @section CAPI_NETWORK_WIFI_CONFIG_MODULE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.wifi\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a device supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="https://developer.tizen.org/development/getting-started/native-application/understanding-tizen-programming/application-filtering"><b>Feature List</b>.</a>
 *
 */

#endif /* __TIZEN_NETWORK_WIFI_DOC_H__ */
