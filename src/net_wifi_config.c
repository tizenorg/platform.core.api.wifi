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

#include "wifi.h"
#include "wifi_config_private.h"
#include "net_wifi_private.h"

/**
 * wifi configuration
 */
EXPORT_API int wifi_config_create(const char *name, const char *passphrase, wifi_security_type_e security_type, wifi_config_h *config)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	struct _wifi_config *h = NULL;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (config == NULL || name == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	h = g_new0(struct _wifi_config, 1);
	if (h == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	h->name = g_strdup(name);
	h->passphrase = g_strdup(passphrase);
	h->security_type = security_type;
	h->is_saved = FALSE;
	h->is_hidden = FALSE;
	h->proxy_address = NULL;
	h->address_family = WIFI_ADDRESS_FAMILY_IPV4;
	h->eap_config = NULL;

	if (security_type == WIFI_SECURITY_TYPE_EAP) {
		h->eap_config = g_new0(struct _wifi_eap_config, 1);
		if (h->eap_config == NULL)
			return WIFI_ERROR_OUT_OF_MEMORY;

		h->eap_config->ca_cert = NULL;
		h->eap_config->client_cert = NULL;
		h->eap_config->private_key = NULL;
		h->eap_config->anonymous_identity = NULL;
		h->eap_config->identity = NULL;
		h->eap_config->subject_match = NULL;
		h->eap_config->eap_type = -1;
		h->eap_config->eap_auth_type = WIFI_EAP_AUTH_TYPE_NONE;
	}

	*config = (wifi_config_h)h;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_clone(wifi_config_h origin, wifi_config_h *cloned_config)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	struct _wifi_config *h = NULL;
	struct _wifi_config *config = NULL;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (origin == NULL || cloned_config == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	config = (struct _wifi_config *)origin;

	h = g_new0(struct _wifi_config, 1);
	if (h == NULL)
		return WIFI_ERROR_OUT_OF_MEMORY;

	h->name = g_strdup(config->name);
	h->passphrase = g_strdup(config->passphrase);
	h->security_type = config->security_type;
	h->is_saved = config->is_saved;
	h->is_hidden = config->is_hidden;
	h->proxy_address = g_strdup(config->proxy_address);
	h->address_family = config->address_family;

	if (config->eap_config) {
		h->eap_config = g_new0(struct _wifi_eap_config, 1);
		if (h->eap_config == NULL)
			return WIFI_ERROR_OUT_OF_MEMORY;

		h->eap_config->ca_cert = g_strdup(config->eap_config->ca_cert);
		h->eap_config->client_cert = g_strdup(config->eap_config->client_cert);
		h->eap_config->private_key = g_strdup(config->eap_config->private_key);
		h->eap_config->anonymous_identity = g_strdup(config->eap_config->anonymous_identity);
		h->eap_config->identity = g_strdup(config->eap_config->identity);
		h->eap_config->subject_match = g_strdup(config->eap_config->subject_match);
		h->eap_config->eap_type = config->eap_config->eap_type;
		h->eap_config->eap_auth_type = config->eap_config->eap_auth_type;
	}

	*cloned_config = (wifi_config_h)h;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_destroy(wifi_config_h config)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	struct _wifi_config *h = (struct _wifi_config *)config;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (config == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	g_free(h->name);
	g_free(h->passphrase);
	g_free(h->proxy_address);
	if (h->eap_config) {
		g_free(h->eap_config->ca_cert);
		g_free(h->eap_config->client_cert);
		g_free(h->eap_config->private_key);
		g_free(h->eap_config->anonymous_identity);
		g_free(h->eap_config->identity);
		g_free(h->eap_config->subject_match);
		g_free(h->eap_config);
	}
	g_free(h);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_save_configuration(wifi_config_h config)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	int ret = WIFI_ERROR_NONE;
	wifi_dbus *dbus_h = NULL;
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (config == NULL || h->name == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	dbus_h = _wifi_get_dbus_handle();
	if (dbus_h == NULL) {
		WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (h->security_type == WIFI_SECURITY_TYPE_EAP) {
		ret = wifi_save_eap_configurations(dbus_h, h->name, h->passphrase, h->security_type, h->proxy_address, h->eap_config, h->is_hidden);
		if (ret != WIFI_ERROR_NONE) {
			WIFI_LOG(WIFI_ERROR, "Fail to wifi_save_eap_configurations");
		}
	}
	else {
		ret = wifi_save_configurations(dbus_h, h->name, h->passphrase, h->security_type, h->proxy_address, h->is_hidden);
		if (ret != WIFI_ERROR_NONE) {
			WIFI_LOG(WIFI_ERROR, "Fail to save configurations [%d]", ret);
		}
	}

	h->is_saved = TRUE;

	return ret;
}

EXPORT_API int wifi_config_foreach_configuration(wifi_config_list_cb callback, void *user_data)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	int ret = WIFI_ERROR_NONE;
	wifi_dbus *dbus_h = NULL;
	GSList *config_ids = NULL;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (callback == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	dbus_h = _wifi_get_dbus_handle();
	if (dbus_h == NULL) {
		WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	config_ids = wifi_config_get_config_id_list(dbus_h);
	if (config_ids == NULL) {
		WIFI_LOG(WIFI_ERROR, "Fail to wifi_get_config_id_list");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	while (config_ids) {
		bool rv = 0;
		struct _wifi_config *h;
		gchar *id = config_ids->data;

		h = g_new0(struct _wifi_config, 1);
		if (h == NULL) {
			ret = WIFI_ERROR_OUT_OF_MEMORY;
			break;
		}

		if (g_str_has_suffix(id, "ieee8021x") == TRUE) {
			h->eap_config = g_new0(struct _wifi_eap_config, 1);
			if (h->eap_config == NULL) {
				ret = WIFI_ERROR_OUT_OF_MEMORY;
				break;
			}
			ret = wifi_load_eap_configurations(dbus_h, id, &h->name,
				&h->security_type, &h->proxy_address, &h->is_hidden, &h->eap_config, &h->last_error);
		}
		else {
			ret = wifi_load_configurations(dbus_h, id, &h->name,
				&h->security_type, &h->proxy_address, &h->is_hidden, &h->last_error);
		}

		if (ret != WIFI_ERROR_NONE) {
			WIFI_LOG(WIFI_ERROR, "Fail to load configurations [%d]", ret);
			return ret;
		}

		h->address_family = WIFI_ADDRESS_FAMILY_IPV4;
		h->is_saved = TRUE;
		rv = callback((wifi_config_h)h, user_data);
		g_free(h->name);
		g_free(h->proxy_address);
		if (h->eap_config) {
			g_free(h->eap_config->ca_cert);
			g_free(h->eap_config->client_cert);
			g_free(h->eap_config->private_key);
			g_free(h->eap_config->anonymous_identity);
			g_free(h->eap_config->identity);
			g_free(h->eap_config->subject_match);
			g_free(h->eap_config);
		}
		g_free(h);

		if (rv == false)
			break;

		config_ids = config_ids->next;
	}

	config_ids = g_slist_nth(config_ids, 0);
	g_slist_free_full(config_ids, g_free);

	return ret;
}

EXPORT_API int wifi_config_get_name(wifi_config_h config, char **name)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	struct _wifi_config *h = (struct _wifi_config *)config;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (config == NULL || name == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (h->name != NULL)
		*name = g_strdup(h->name);
	else
		*name = NULL;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_get_security_type(wifi_config_h config, wifi_security_type_e *security_type)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	struct _wifi_config *h = (struct _wifi_config *)config;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (config == NULL || security_type == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	*security_type = h->security_type;

	return WIFI_ERROR_NONE;
}

/**
 * wifi configuration set field
 */
EXPORT_API int wifi_config_set_proxy_address(wifi_config_h config, wifi_address_family_e address_family, const char *proxy_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	struct _wifi_config *h = (struct _wifi_config *)config;
	int ret = WIFI_ERROR_NONE;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (config == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}
	if ((address_family != WIFI_ADDRESS_FAMILY_IPV4 && address_family != WIFI_ADDRESS_FAMILY_IPV6)) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	if (address_family == WIFI_ADDRESS_FAMILY_IPV6) {
		WIFI_LOG(WIFI_ERROR, "Not supported yet");
		return WIFI_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED;
	}

	h->address_family = address_family;
	h->proxy_address = g_strdup(proxy_address);

	if (h->is_saved == TRUE) {
		wifi_dbus *dbus_h = NULL;
		gchar *config_id = NULL;

		dbus_h = _wifi_get_dbus_handle();
		if (dbus_h == NULL) {
			WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
			return WIFI_ERROR_INVALID_OPERATION;
		}

		config_id = wifi_config_get_config_id(h->name, h->security_type);

		ret = wifi_configuration_set_field(dbus_h, config_id, WIFI_CONFIG_PROXYADDRESS, proxy_address);
		if (ret != WIFI_ERROR_NONE) {
			WIFI_LOG(WIFI_ERROR, "Fail to set proxy address [%d]", ret);
		}

		g_free(config_id);
	}

	return ret;
}

EXPORT_API int wifi_config_get_proxy_address(wifi_config_h config, wifi_address_family_e *address_family, char **proxy_address)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	struct _wifi_config *h = (struct _wifi_config *)config;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (config == NULL || address_family == NULL || proxy_address == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	*address_family = h->address_family;
	*proxy_address = g_strdup(h->proxy_address);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_set_hidden_ap_property(wifi_config_h config, bool hidden)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	struct _wifi_config *h = (struct _wifi_config *)config;
	int ret = WIFI_ERROR_NONE;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (config == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	h->is_hidden = hidden;

	if (h->is_saved == TRUE) {
		wifi_dbus *dbus_h = NULL;
		char *config_id = NULL;
		char *hidden = NULL;

		dbus_h = _wifi_get_dbus_handle();
		if (dbus_h == NULL) {
			WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
			return WIFI_ERROR_INVALID_OPERATION;
		}

		config_id = wifi_config_get_config_id(h->name, h->security_type);

		if (h->is_hidden == TRUE) {
			hidden = g_strdup("TRUE");
		} else {
			hidden = g_strdup("FALSE");
		}
		ret = wifi_configuration_set_field(dbus_h, config_id, WIFI_CONFIG_HIDDEN, hidden);
		if (ret != WIFI_ERROR_NONE) {
			WIFI_LOG(WIFI_ERROR, "Fail to set hidden [%d]", ret);
		}

		g_free(hidden);
		g_free(config_id);
	}

	return ret;
}

EXPORT_API int wifi_config_get_hidden_ap_property(wifi_config_h config, bool *hidden)
{
	CHECK_FEATURE_SUPPORTED(WIFI_FEATURE);

	struct _wifi_config *h = (struct _wifi_config *)config;

	if (_wifi_is_init() == false) {
		WIFI_LOG(WIFI_ERROR, "Not initialized");
		return WIFI_ERROR_INVALID_OPERATION;
	}

	if (config == NULL || hidden == NULL) {
		WIFI_LOG(WIFI_ERROR, "Invalid parameter");
		return WIFI_ERROR_INVALID_PARAMETER;
	}

	*hidden = h->is_hidden;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_get_eap_anonymous_identity(wifi_config_h config, char** anonymous_identity)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (anonymous_identity == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	*anonymous_identity = g_strdup(h->eap_config->anonymous_identity);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_set_eap_anonymous_identity(wifi_config_h config, const char* anonymous_identity)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	h->eap_config->anonymous_identity = g_strdup(anonymous_identity);

	if (h->is_saved == TRUE) {
		wifi_dbus *dbus_h = NULL;
		gchar *config_id = NULL;

		dbus_h = _wifi_get_dbus_handle();
		if (dbus_h == NULL) {
			WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
			return WIFI_ERROR_INVALID_OPERATION;
		}

		config_id = wifi_config_get_config_id(h->name, h->security_type);

		wifi_configuration_set_field(dbus_h, config_id, WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY, anonymous_identity);

		g_free(config_id);
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_get_eap_ca_cert_file(wifi_config_h config, char** ca_cert)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (ca_cert == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	*ca_cert = g_strdup(h->eap_config->ca_cert);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_set_eap_ca_cert_file(wifi_config_h config, const char* ca_cert)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	h->eap_config->ca_cert = g_strdup(ca_cert);

	if (h->is_saved == TRUE) {
		wifi_dbus *dbus_h = NULL;
		gchar *config_id = NULL;

		dbus_h = _wifi_get_dbus_handle();
		if (dbus_h == NULL) {
			WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
			return WIFI_ERROR_INVALID_OPERATION;
		}

		config_id = wifi_config_get_config_id(h->name, h->security_type);

		wifi_configuration_set_field(dbus_h, config_id, WIFI_CONFIG_EAP_CACERT, ca_cert);

		g_free(config_id);
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_get_eap_client_cert_file(wifi_config_h config, char** client_cert)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (client_cert == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	*client_cert = g_strdup(h->eap_config->client_cert);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_set_eap_client_cert_file(wifi_config_h config, const char* private_key, const char* client_cert)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	h->eap_config->private_key = g_strdup(private_key);
	h->eap_config->client_cert = g_strdup(client_cert);

	if (h->is_saved == TRUE) {
		wifi_dbus *dbus_h = NULL;
		gchar *config_id = NULL;

		dbus_h = _wifi_get_dbus_handle();
		if (dbus_h == NULL) {
			WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
			return WIFI_ERROR_INVALID_OPERATION;
		}

		config_id = wifi_config_get_config_id(h->name, h->security_type);

		wifi_configuration_set_field(dbus_h, config_id, WIFI_CONFIG_EAP_CLIENTCERT, client_cert);
		wifi_configuration_set_field(dbus_h, config_id, WIFI_CONFIG_EAP_PRIVATEKEY, private_key);

		g_free(config_id);
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_get_eap_identity(wifi_config_h config, char** identity)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (identity == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	*identity = g_strdup(h->eap_config->identity);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_set_eap_identity(wifi_config_h config, const char* identity)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	h->eap_config->identity = g_strdup(identity);

	if (h->is_saved == TRUE) {
		wifi_dbus *dbus_h = NULL;
		gchar *config_id = NULL;

		dbus_h = _wifi_get_dbus_handle();
		if (dbus_h == NULL) {
			WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
			return WIFI_ERROR_INVALID_OPERATION;
		}

		config_id = wifi_config_get_config_id(h->name, h->security_type);

		wifi_configuration_set_field(dbus_h, config_id, WIFI_CONFIG_EAP_IDENTITY, identity);

		g_free(config_id);
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_get_eap_type(wifi_config_h config, wifi_eap_type_e *eap_type)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (eap_type == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	*eap_type = h->eap_config->eap_type;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_set_eap_type(wifi_config_h config, wifi_eap_type_e eap_type)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	h->eap_config->eap_type = eap_type;

	if (h->is_saved == TRUE) {
		wifi_dbus *dbus_h = NULL;
		gchar *config_id = NULL;
		gchar *value = NULL;

		dbus_h = _wifi_get_dbus_handle();
		if (dbus_h == NULL) {
			WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
			return WIFI_ERROR_INVALID_OPERATION;
		}

		config_id = wifi_config_get_config_id(h->name, h->security_type);

		value = wifi_eap_type_to_string(eap_type);

		wifi_configuration_set_field(dbus_h, config_id, WIFI_CONFIG_EAP_TYPE, value);

		g_free(config_id);
		g_free(value);
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_get_eap_auth_type(wifi_config_h config, wifi_eap_auth_type_e* eap_auth_type)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (eap_auth_type == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	*eap_auth_type = h->eap_config->eap_auth_type;

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_set_eap_auth_type(wifi_config_h config, wifi_eap_auth_type_e eap_auth_type)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	h->eap_config->eap_auth_type = eap_auth_type;

	if (h->is_saved == TRUE) {
		wifi_dbus *dbus_h = NULL;
		gchar *config_id = NULL;
		gchar *value = NULL;

		dbus_h = _wifi_get_dbus_handle();
		if (dbus_h == NULL) {
			WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
			return WIFI_ERROR_INVALID_OPERATION;
		}

		config_id = wifi_config_get_config_id(h->name, h->security_type);

		value = wifi_eap_auth_type_to_string(eap_auth_type);

		wifi_configuration_set_field(dbus_h, config_id, WIFI_CONFIG_EAP_AUTH_TYPE, value);

		g_free(config_id);
		g_free(value);
	}

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_get_eap_subject_match(wifi_config_h config, char** subject_match)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (subject_match == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	*subject_match = g_strdup(h->eap_config->subject_match);

	return WIFI_ERROR_NONE;
}

EXPORT_API int wifi_config_set_eap_subject_match(wifi_config_h config, const char* subject_match)
{
	struct _wifi_config *h = (struct _wifi_config *)config;

	if (config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;
	if (h->eap_config == NULL)
		return WIFI_ERROR_INVALID_PARAMETER;

	h->eap_config->subject_match = g_strdup(subject_match);

	if (h->is_saved == TRUE) {
		wifi_dbus *dbus_h = NULL;
		gchar *config_id = NULL;

		dbus_h = _wifi_get_dbus_handle();
		if (dbus_h == NULL) {
			WIFI_LOG(WIFI_ERROR, "Not initialized for wifi dbus connection");
			return WIFI_ERROR_INVALID_OPERATION;
		}

		config_id = wifi_config_get_config_id(h->name, h->security_type);

		wifi_configuration_set_field(dbus_h, config_id, WIFI_CONFIG_EAP_SUBJECT_MATCH, subject_match);

		g_free(config_id);
	}

	return WIFI_ERROR_NONE;
}
