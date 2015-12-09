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
#include <string.h>

#include "wifi.h"
#include "wifi_dbus_private.h"
#include "wifi_config_private.h"
#include "net_wifi_private.h"

#define WIFI_SECURITY_NONE			"none"
#define WIFI_SECURITY_WEP			"wep"
#define WIFI_SECURITY_WPA_PSK		"psk"
#define WIFI_SECURITY_EAP			"ieee8021x"

static wifi_error_e _wifi_error_to_enum(const gchar *error)
{
	if (NULL != strstr(error, "NoReply"))
		return WIFI_ERROR_NO_REPLY;
	else if (NULL != strstr(error, "Failed"))
		return WIFI_ERROR_INVALID_OPERATION;
	else if (NULL != strstr(error, "UnknownMethod"))
		return WIFI_ERROR_INVALID_OPERATION;
	else if (NULL != strstr(error, "InvalidArguments"))
		return WIFI_ERROR_INVALID_PARAMETER;
	else if (NULL != strstr(error, "AccessDenied"))
		return WIFI_ERROR_PERMISSION_DENIED;
	else if (NULL != strstr(error, "PermissionDenied"))
		return WIFI_ERROR_PERMISSION_DENIED;
	else if (NULL != strstr(error, "PassphraseRequired"))
		return WIFI_ERROR_INVALID_OPERATION;
	else if (NULL != strstr(error, "NotRegistered"))
		return WIFI_ERROR_INVALID_OPERATION;
	else if (NULL != strstr(error, "NotUnique"))
		return WIFI_ERROR_INVALID_OPERATION;
	else if (NULL != strstr(error, "NotSupported"))
		return WIFI_ERROR_NOT_SUPPORTED;
	else if (NULL != strstr(error, "NotImplemented"))
		return WIFI_ERROR_NOT_SUPPORTED;
	else if (NULL != strstr(error, "NotFound"))
		return WIFI_ERROR_NOT_SUPPORTED;
	else if (NULL != strstr(error, "NoCarrier"))
		return WIFI_ERROR_NOT_SUPPORTED;
	else if (NULL != strstr(error, "InProgress"))
		return WIFI_ERROR_NOW_IN_PROGRESS;
	else if (NULL != strstr(error, "AlreadyExists"))
		return WIFI_ERROR_INVALID_OPERATION;
	else if (NULL != strstr(error, "AlreadyEnabled"))
		return WIFI_ERROR_INVALID_OPERATION;
	else if (NULL != strstr(error, "AlreadyDisabled"))
		return WIFI_ERROR_INVALID_OPERATION;
	else if (NULL != strstr(error, "AlreadyConnected"))
		return WIFI_ERROR_ALREADY_EXISTS;
	else if (NULL != strstr(error, "NotConnected"))
		return WIFI_ERROR_NO_CONNECTION;
	else if (NULL != strstr(error, "OperationAborted"))
		return WIFI_ERROR_OPERATION_FAILED;
	else if (NULL != strstr(error, "OperationTimeout"))
		return WIFI_ERROR_OPERATION_FAILED;
	else if (NULL != strstr(error, "InvalidService"))
		return WIFI_ERROR_INVALID_OPERATION;
	else if (NULL != strstr(error, "InvalidProperty"))
		return WIFI_ERROR_INVALID_OPERATION;
	return WIFI_ERROR_INVALID_OPERATION;
}

static wifi_error_e _wifi_last_error_to_enum(const gchar *last_error)
{
	wifi_error_e ret = WIFI_ERROR_OPERATION_FAILED;

	if (g_strcmp0(last_error, "ERROR_NONE") == 0) {
		ret = WIFI_ERROR_NONE;
	} else if (g_strcmp0(last_error, "invalid-key") == 0) {
		ret = WIFI_ERROR_INVALID_KEY;
	} else if (g_strcmp0(last_error, "dhcp-failed") == 0) {
		ret = WIFI_ERROR_DHCP_FAILED;
	} else {
		WIFI_LOG(WIFI_ERROR, "Not supported error type (%s)", last_error);
		ret = WIFI_ERROR_NONE;
	}

	return ret;
}

static gchar *_wifi_change_name_to_hexadecimal(const gchar *name)
{
	GString *string;
	gint i = 0;
	gint length = 0;
	gchar *hex = NULL;

	if (name == NULL)
		return NULL;

	length = strlen(name);

	string = g_string_sized_new((gsize)(length * 2));
	if (string == NULL)
		return NULL;

	for (i = 0; i < length; i++)
		g_string_append_printf(string, "%02x", name[i]);

	hex = g_strdup_printf("%s", string->str);
	g_string_free(string, TRUE);

	return hex;
}

gchar *wifi_eap_type_to_string(wifi_eap_type_e eap_type)
{
	gchar *type = NULL;

	switch (eap_type) {
	case WIFI_EAP_TYPE_PEAP:
		type = g_strdup("PEAP");
		break;
	case WIFI_EAP_TYPE_TLS:
		type = g_strdup("TLS");
		break;
	case WIFI_EAP_TYPE_TTLS:
		type = g_strdup("TTLS");
		break;
	case WIFI_EAP_TYPE_SIM:
		type = g_strdup("SIM");
		break;
	case WIFI_EAP_TYPE_AKA:
		type = g_strdup("AKA");
		break;
	}
	return type;
}

gchar *wifi_eap_auth_type_to_string(wifi_eap_auth_type_e eap_auth_type)
{
	gchar *type = NULL;

	switch (eap_auth_type) {
	case WIFI_EAP_AUTH_TYPE_PAP:
		type = g_strdup("PAP");
		break;
	case WIFI_EAP_AUTH_TYPE_MSCHAP:
		type = g_strdup("MSCHAP");
		break;
	case WIFI_EAP_AUTH_TYPE_MSCHAPV2:
		type = g_strdup("MSCHAPV2");
		break;
	case WIFI_EAP_AUTH_TYPE_GTC:
		type = g_strdup("GTC");
		break;
	case WIFI_EAP_AUTH_TYPE_MD5:
		type = g_strdup("MD5");
		break;
	default:
	case WIFI_EAP_AUTH_TYPE_NONE:
		type = NULL;
		break;
	}
	return type;
}

wifi_eap_type_e wifi_eap_type_to_int(const gchar *type)
{
	wifi_eap_type_e ret = -1;

	if (type == NULL)
		return ret;

	if (g_strcmp0(type, "PEAP") == 0)
		ret = WIFI_EAP_TYPE_PEAP;
	else if (g_strcmp0(type, "TLS") == 0)
		ret = WIFI_EAP_TYPE_TLS;
	else if (g_strcmp0(type, "TTLS") == 0)
		ret = WIFI_EAP_TYPE_TTLS;
	else if (g_strcmp0(type, "SIM") == 0)
		ret = WIFI_EAP_TYPE_SIM;
	else if (g_strcmp0(type, "AKA") == 0)
		ret = WIFI_EAP_TYPE_AKA;
	else
		WIFI_LOG(WIFI_ERROR, "Not supported type (%s)", type);

	return ret;
}

wifi_eap_auth_type_e wifi_eap_auth_type_to_int(const gchar *type)
{
	wifi_eap_auth_type_e ret = WIFI_EAP_AUTH_TYPE_NONE;

	if (type == NULL)
		return ret;

	if (g_strcmp0(type, "PAP") == 0)
		ret = WIFI_EAP_AUTH_TYPE_PAP;
	else if (g_strcmp0(type, "MSCHAP") == 0)
		ret = WIFI_EAP_AUTH_TYPE_MSCHAP;
	else if (g_strcmp0(type, "MSCHAPV2") == 0)
		ret = WIFI_EAP_AUTH_TYPE_MSCHAPV2;
	else if (g_strcmp0(type, "GTC") == 0)
		ret = WIFI_EAP_AUTH_TYPE_GTC;
	else if (g_strcmp0(type, "MD5") == 0)
		ret = WIFI_EAP_AUTH_TYPE_MD5;
	else
		WIFI_LOG(WIFI_ERROR, "Not supported type (%s)", type);

	return ret;
}

static wifi_security_type_e _wifi_security_type_to_int(const gchar *type)
{
	wifi_security_type_e ret = WIFI_SECURITY_TYPE_NONE;

	if (type == NULL)
		return ret;

	if (g_strcmp0(type, WIFI_SECURITY_NONE) == 0)
		ret = WIFI_SECURITY_TYPE_NONE;
	else if (g_strcmp0(type, WIFI_SECURITY_WEP) == 0)
		ret = WIFI_SECURITY_TYPE_WEP;
	else if (g_strcmp0(type, WIFI_SECURITY_WPA_PSK) == 0)
		ret = WIFI_SECURITY_TYPE_WPA_PSK;
	else if (g_strcmp0(type, WIFI_SECURITY_EAP) == 0)
		ret = WIFI_SECURITY_TYPE_EAP;
	else
		WIFI_LOG(WIFI_ERROR, "Not supported type (%s)", type);

	return ret;
}

static gchar *_wifi_security_type_to_string(wifi_security_type_e security_type)
{
	switch (security_type) {
	case WIFI_SECURITY_TYPE_NONE:
		return WIFI_SECURITY_NONE;

	case WIFI_SECURITY_TYPE_WEP:
		return WIFI_SECURITY_WEP;

	case WIFI_SECURITY_TYPE_WPA_PSK:
	case WIFI_SECURITY_TYPE_WPA2_PSK:
		return WIFI_SECURITY_WPA_PSK;

	case WIFI_SECURITY_TYPE_EAP:
		return WIFI_SECURITY_EAP;

	default:
		return NULL;
	}
}

int wifi_config_get_last_error(wifi_config_h config, wifi_error_e *last_error)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	struct _wifi_config *h = (struct _wifi_config *)config;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (config == NULL || last_error == NULL) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	*last_error = h->last_error;

	return WIFI_ERROR_NONE;
}

gchar *wifi_config_get_config_id(const gchar *name, wifi_security_type_e security_type)
{
	gchar *config_id = NULL;
	gchar *ssid = NULL;
	gchar *type = NULL;

	ssid = _wifi_change_name_to_hexadecimal(name);
	type = g_strdup(_wifi_security_type_to_string(security_type));
	config_id = g_strdup_printf("%s_managed_%s", ssid, type);

	g_free(ssid);
	g_free(type);

	return config_id;
}

GSList *wifi_config_get_config_id_list(wifi_dbus *handle)
{
	GError *error = NULL;
	GVariant *result = NULL;
	GVariantIter *iter = NULL;
	GSList *list = NULL;
	gchar *config_id = NULL;

	result = g_dbus_connection_call_sync(handle->dbus_conn,
					     NETCONFIG_SERVICE,
					     NETCONFIG_WIFI_PATH,
					     NETCONFIG_IWIFI,
					     "GetConfigIds",
					     g_variant_new("()"),
					     NULL, G_DBUS_CALL_FLAGS_NONE,
					     DBUS_REPLY_TIMEOUT, handle->ca,
					     &error);

	if (error) {
		WIFI_LOG(WIFI_ERROR, "Fail to GetConfigId [%d: %s]", error->code, error->message);
		g_error_free(error);
		return NULL;
	}

	g_variant_get(result, "(as)", &iter);
	while (g_variant_iter_loop(iter, "s", &config_id))
		list = g_slist_append(list, g_strdup(config_id));

	g_variant_iter_free(iter);
	g_variant_unref(result);


	return list;
}

int wifi_save_configurations(wifi_dbus *handle, const gchar *name, const gchar *passphrase, wifi_security_type_e security_type, const gchar *proxy_address, gboolean is_hidden)
{
	wifi_error_e ret = WIFI_ERROR_NONE;
	GError *error = NULL;
	GVariant *result = NULL;
	GVariant *params = NULL;
	GVariantBuilder *b = NULL;
	gchar *config_id = NULL;
	gchar *ssid = NULL;

	if (security_type != WIFI_SECURITY_TYPE_NONE) {
		if (passphrase == NULL) {
			WIFI_LOG(WIFI_ERROR, "Fail to wifi_save_configurations [secu_type is not NONE[%d] but passphrase is NULL]", security_type);
			return WIFI_ERROR_INVALID_PARAMETER;
		} else {
			if (strlen(passphrase) == 0) {
				WIFI_LOG(WIFI_ERROR, "Fail to wifi_save_configurations passphrase length is 0");
				return WIFI_ERROR_INVALID_PARAMETER;
			}
		}
	}

	config_id = wifi_config_get_config_id(name, security_type);
	ssid = _wifi_change_name_to_hexadecimal(name);

	b = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(b, "{sv}", WIFI_CONFIG_NAME, g_variant_new_string(name));
	g_variant_builder_add(b, "{sv}", WIFI_CONFIG_SSID, g_variant_new_string(ssid));
	if (passphrase != NULL)
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_PASSPHRASE, g_variant_new_string(passphrase));
	if (proxy_address != NULL)
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_PROXYADDRESS, g_variant_new_string(proxy_address));
	if (is_hidden == TRUE)
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_HIDDEN, g_variant_new_string("TRUE"));

	params = g_variant_new("(s@a{sv})", config_id, g_variant_builder_end(b));
	g_variant_builder_unref(b);
	g_free(config_id);

	result = g_dbus_connection_call_sync(handle->dbus_conn,
					     NETCONFIG_SERVICE,
					     NETCONFIG_WIFI_PATH,
					     NETCONFIG_IWIFI,
					     "SaveConfiguration",
					     params,
					     NULL, G_DBUS_CALL_FLAGS_NONE,
					     DBUS_REPLY_TIMEOUT, handle->ca,
					     &error);

	if (error) {
		WIFI_LOG(WIFI_ERROR, "Fail to SaveConfiguration [%d: %s]", error->code, error->message);
		ret = _wifi_error_to_enum(error->message);
		g_error_free(error);
	}

	if (result != NULL)
		g_variant_unref(result);

	return ret;
}

int wifi_load_configurations(wifi_dbus *handle, const gchar *config_id, gchar **name, wifi_security_type_e *security_type, gchar **proxy_address, gboolean *is_hidden, wifi_error_e *last_error)
{
	GError *error = NULL;
	GVariant *result = NULL;
	wifi_error_e ret = WIFI_ERROR_NONE;

	result = g_dbus_connection_call_sync(handle->dbus_conn,
					     NETCONFIG_SERVICE,
					     NETCONFIG_WIFI_PATH,
					     NETCONFIG_IWIFI,
					     "LoadConfiguration",
					     g_variant_new("(s)", config_id),
					     NULL, G_DBUS_CALL_FLAGS_NONE,
					     DBUS_REPLY_TIMEOUT, handle->ca,
					     &error);

	if (error) {
		WIFI_LOG(WIFI_ERROR, "Fail to LoadConfiguration [%d: %s]", error->code, error->message);
		ret = _wifi_error_to_enum(error->message);
		g_error_free(error);
		return ret;
	}

	if (result) {
		GVariantIter *iter;
		gchar *field;
		GVariant *value;

		g_variant_get(result, "(a{sv})", &iter);
		while (g_variant_iter_loop(iter, "{sv}", &field, &value)) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				if (g_strcmp0(field, WIFI_CONFIG_NAME) == 0) {
					*name = g_strdup(g_variant_get_string(value, NULL));
				} else if (g_strcmp0(field, WIFI_CONFIG_SECURITY_TYPE) == 0) {
					*security_type = _wifi_security_type_to_int(g_variant_get_string(value, NULL));
				} else if (g_strcmp0(field, WIFI_CONFIG_HIDDEN) == 0) {
					const gchar *r_hidden = g_variant_get_string(value, NULL);
					if (g_strcmp0(r_hidden, "TRUE") == 0)
						*is_hidden = TRUE;
					else
						*is_hidden = FALSE;
				} else if (g_strcmp0(field, WIFI_CONFIG_PROXYADDRESS) == 0) {
					const gchar *r_proxy_address = g_variant_get_string(value, NULL);
					if (g_strcmp0(r_proxy_address, "NONE") == 0)
						*proxy_address = NULL;
					else
						*proxy_address = g_strdup(r_proxy_address);
				} else if (g_strcmp0(field, WIFI_CONFIG_FAILURE) == 0) {
					*last_error = _wifi_last_error_to_enum(g_variant_get_string(value, NULL));
				}
			}
		}

		g_variant_iter_free(iter);
		g_variant_unref(result);
	}

	return WIFI_ERROR_NONE;
}

int wifi_save_eap_configurations(wifi_dbus *handle, const gchar *name, const gchar *passphrase, wifi_security_type_e security_type, const gchar *proxy_address, struct _wifi_eap_config *eap_config, gboolean is_hidden)
{
	wifi_error_e ret = WIFI_ERROR_NONE;
	GError *error = NULL;
	GVariant *result = NULL;
	GVariant *params = NULL;
	GVariantBuilder *b = NULL;
	gchar *config_id = NULL;
	gchar *ssid = NULL;

	if (security_type != WIFI_SECURITY_TYPE_EAP) {
		WIFI_LOG(WIFI_ERROR, "Fail to wifi_save_configurations [secu_type is not EAP[%d]]", security_type);
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (security_type != WIFI_SECURITY_TYPE_NONE) {
		if (security_type == (WIFI_EAP_TYPE_SIM | WIFI_EAP_TYPE_AKA)) {
			WIFI_LOG(WIFI_INFO, "security_type: %d", security_type);
			goto eap_save_config;
		}
		if (passphrase == NULL) {
			WIFI_LOG(WIFI_ERROR, "Fail to wifi_save_configurations [secu_type is not NONE[%d] but passphrase is NULL]", security_type);
			return WIFI_ERROR_INVALID_PARAMETER;
		} else {
			if (strlen(passphrase) == 0) {
				WIFI_LOG(WIFI_ERROR, "Fail to wifi_save_configurations passphrase length is 0");
				return WIFI_ERROR_INVALID_PARAMETER;
			}
		}
	}

eap_save_config:
	config_id = wifi_config_get_config_id(name, security_type);
	ssid = _wifi_change_name_to_hexadecimal(name);

	b = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(b, "{sv}", WIFI_CONFIG_NAME, g_variant_new_string(name));
	g_variant_builder_add(b, "{sv}", WIFI_CONFIG_SSID, g_variant_new_string(ssid));
	if (passphrase != NULL)
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_PASSPHRASE, g_variant_new_string(passphrase));
	if (proxy_address != NULL)
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_PROXYADDRESS, g_variant_new_string(proxy_address));
	if (is_hidden == TRUE)
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_HIDDEN, g_variant_new_string("TRUE"));

	if (eap_config != NULL) {
		gchar* auth_type = NULL;
		gchar* eap_type = NULL;
		if (eap_config->anonymous_identity != NULL)
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY, g_variant_new_string(eap_config->anonymous_identity));
		if (eap_config->ca_cert != NULL)
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_CACERT, g_variant_new_string(eap_config->ca_cert));
		if (eap_config->client_cert != NULL)
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_CLIENTCERT, g_variant_new_string(eap_config->client_cert));
		if (eap_config->private_key != NULL)
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_PRIVATEKEY, g_variant_new_string(eap_config->private_key));
		if (eap_config->identity != NULL)
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_IDENTITY, g_variant_new_string(eap_config->identity));
		if (eap_config->subject_match != NULL)
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_SUBJECT_MATCH, g_variant_new_string(eap_config->subject_match));

		auth_type = wifi_eap_auth_type_to_string(eap_config->eap_auth_type);
		if (auth_type != NULL)
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_AUTH_TYPE, g_variant_new_string(auth_type));

		eap_type = wifi_eap_type_to_string(eap_config->eap_type);
		if (eap_type != NULL)
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_TYPE, g_variant_new_string(eap_type));

		g_free(auth_type);
		g_free(eap_type);
	}

	params = g_variant_new("(s@a{sv})", config_id, g_variant_builder_end(b));
	g_variant_builder_unref(b);
	g_free(config_id);

	result = g_dbus_connection_call_sync(handle->dbus_conn,
					     NETCONFIG_SERVICE,
					     NETCONFIG_WIFI_PATH,
					     NETCONFIG_IWIFI,
					     "SaveEapConfiguration",
					     params,
					     NULL, G_DBUS_CALL_FLAGS_NONE,
					     DBUS_REPLY_TIMEOUT, handle->ca,
					     &error);

	if (error) {
		WIFI_LOG(WIFI_ERROR, "Fail to SaveEapConfiguration [%d: %s]", error->code, error->message);
		ret = _wifi_error_to_enum(error->message);
		g_error_free(error);
	}

	if (result != NULL)
		g_variant_unref(result);

	return ret;
}

int wifi_load_eap_configurations(wifi_dbus *handle, const gchar *config_id, gchar **name, wifi_security_type_e *security_type, gchar **proxy_address, gboolean *is_hidden, struct _wifi_eap_config **eap_config, wifi_error_e *last_error)
{
	GError *error = NULL;
	GVariant *result = NULL;

	result = g_dbus_connection_call_sync(handle->dbus_conn,
					     NETCONFIG_SERVICE,
					     NETCONFIG_WIFI_PATH,
					     NETCONFIG_IWIFI,
					     "LoadEapConfiguration",
					     g_variant_new("(s)", config_id),
					     NULL, G_DBUS_CALL_FLAGS_NONE,
					     DBUS_REPLY_TIMEOUT, handle->ca,
					     &error);

	if (result) {
		GVariantIter *iter;
		gchar *field;
		GVariant *value;

		g_variant_get(result, "(a{sv})", &iter);
		while (g_variant_iter_loop(iter, "{sv}", &field, &value)) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				if (g_strcmp0(field, WIFI_CONFIG_NAME) == 0) {
					*name = g_strdup(g_variant_get_string(value, NULL));
				} else if (g_strcmp0(field, WIFI_CONFIG_SECURITY_TYPE) == 0) {
					*security_type = _wifi_security_type_to_int(g_variant_get_string(value, NULL));
				} else if (g_strcmp0(field, WIFI_CONFIG_HIDDEN) == 0) {
					const gchar *r_hidden = g_variant_get_string(value, NULL);
					if (g_strcmp0(r_hidden, "TRUE") == 0)
						*is_hidden = TRUE;
					else
						*is_hidden = FALSE;
				} else if (g_strcmp0(field, WIFI_CONFIG_PROXYADDRESS) == 0) {
					const gchar *r_proxy_address = g_variant_get_string(value, NULL);
					if (g_strcmp0(r_proxy_address, "NONE") == 0)
						*proxy_address = NULL;
					else
						*proxy_address = g_strdup(r_proxy_address);
				} else if (g_strcmp0(field, WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY) == 0) {
					const gchar *anonymous_identity = g_variant_get_string(value, NULL);
					(*eap_config)->anonymous_identity = g_strdup(anonymous_identity);
				} else if (g_strcmp0(field, WIFI_CONFIG_EAP_CACERT) == 0) {
					const gchar *ca_cert = g_variant_get_string(value, NULL);
					(*eap_config)->ca_cert = g_strdup(ca_cert);
				} else if (g_strcmp0(field, WIFI_CONFIG_EAP_CLIENTCERT) == 0) {
					const gchar *client_cert = g_variant_get_string(value, NULL);
					(*eap_config)->client_cert = g_strdup(client_cert);
				} else if (g_strcmp0(field, WIFI_CONFIG_EAP_PRIVATEKEY) == 0) {
					const gchar *private_key = g_variant_get_string(value, NULL);
					(*eap_config)->private_key = g_strdup(private_key);
				} else if (g_strcmp0(field, WIFI_CONFIG_EAP_IDENTITY) == 0) {
					const gchar *identity = g_variant_get_string(value, NULL);
					(*eap_config)->identity = g_strdup(identity);
				} else if (g_strcmp0(field, WIFI_CONFIG_EAP_TYPE) == 0) {
					const gchar *eap_type = g_variant_get_string(value, NULL);
					(*eap_config)->eap_type = wifi_eap_type_to_int(eap_type);
				} else if (g_strcmp0(field, WIFI_CONFIG_EAP_AUTH_TYPE) == 0) {
					const gchar *auth_type = g_variant_get_string(value, NULL);
					(*eap_config)->eap_auth_type = wifi_eap_auth_type_to_int(auth_type);
				} else if (g_strcmp0(field, WIFI_CONFIG_EAP_SUBJECT_MATCH) == 0) {
					const gchar *subject_match = g_variant_get_string(value, NULL);
					(*eap_config)->subject_match = g_strdup(subject_match);
				} else if (g_strcmp0(field, WIFI_CONFIG_FAILURE) == 0) {
					*last_error = _wifi_last_error_to_enum(g_variant_get_string(value, NULL));
				}
			}
		}
		g_variant_iter_free(iter);
		g_variant_unref(result);
	}

	return WIFI_ERROR_NONE;
}

int wifi_configuration_set_field(wifi_dbus *handle, const gchar *config_id, const gchar *key, const gchar *value)
{
	wifi_error_e ret = WIFI_ERROR_NONE;
	GError *error = NULL;
	GVariant *result = NULL;

	result = g_dbus_connection_call_sync(handle->dbus_conn,
					     NETCONFIG_SERVICE,
					     NETCONFIG_WIFI_PATH,
					     NETCONFIG_IWIFI,
					     "SetConfigField",
					     g_variant_new("(sss)", config_id, key, value),
					     NULL, G_DBUS_CALL_FLAGS_NONE,
					     DBUS_REPLY_TIMEOUT, handle->ca,
					     &error);

	if (error) {
		WIFI_LOG(WIFI_ERROR, "Fail to SetConfigField [%d: %s]", error->code, error->message);
		ret = _wifi_error_to_enum(error->message);
		g_error_free(error);
	}

	if (result != NULL)
		g_variant_unref(result);

	return ret;
}

int wifi_configuration_get_passphrase(wifi_dbus *handle, const gchar *config_id, gchar **passphrase)
{
	wifi_error_e ret = WIFI_ERROR_NONE;
	GError *error = NULL;
	GVariant *result = NULL;
	gchar *val = NULL;

	result = g_dbus_connection_call_sync(handle->dbus_conn,
					     NETCONFIG_SERVICE,
					     NETCONFIG_WIFI_PATH,
					     NETCONFIG_IWIFI,
					     "GetConfigPassphrase",
					     g_variant_new("(s)", config_id),
					     NULL, G_DBUS_CALL_FLAGS_NONE,
					     DBUS_REPLY_TIMEOUT, handle->ca,
					     &error);

	if (error) {
		WIFI_LOG(WIFI_ERROR, "Fail to GetConfigPassphrase [%d: %s]", error->code, error->message);
		ret = _wifi_error_to_enum(error->message);
		g_error_free(error);
		return ret;
	}

	if (result != NULL) {
		g_variant_get(result, "(s)", &val);
		g_variant_unref(result);
	}

	*passphrase = g_strdup(val);
	g_free(val);

	return ret;
}
