#ifndef __WIFI_CONFIG_H__
#define __WIFI_CONFIG_H__

#include <glib.h>

#include "wifi.h"
#include "wifi_dbus_private.h"

#define WIFI_CONFIG_NAME                        "Name"
#define WIFI_CONFIG_SSID                "SSID"
#define WIFI_CONFIG_PASSPHRASE                  "Passphrase"
#define WIFI_CONFIG_SECURITY_TYPE       "Security"
#define WIFI_CONFIG_PROXYADDRESS                "ProxyAddress"
#define WIFI_CONFIG_HIDDEN                              "Hidden"
#define WIFI_CONFIG_FAILURE			"Failure"
#define WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY			"AnonymousIdentity"
#define WIFI_CONFIG_EAP_CACERT			"CACertFile"
#define WIFI_CONFIG_EAP_CLIENTCERT			"ClientCertFile"
#define WIFI_CONFIG_EAP_PRIVATEKEY		"PrivateKeyFile"
#define WIFI_CONFIG_EAP_IDENTITY		"Identity"
#define WIFI_CONFIG_EAP_TYPE		"EapType"
#define WIFI_CONFIG_EAP_AUTH_TYPE	"EapAuthType"
#define WIFI_CONFIG_EAP_SUBJECT_MATCH	"SubjectMatch"

struct _wifi_eap_config {
	gchar *ca_cert;
	gchar *private_key;
	gchar *client_cert;
	gchar *anonymous_identity;
	gchar *identity;
	gchar *subject_match;
	wifi_eap_type_e eap_type;
	wifi_eap_auth_type_e eap_auth_type;
};

struct _wifi_config {
	// mandatory
	gchar *name;
	gchar *passphrase;
	wifi_security_type_e security_type;
	gboolean is_saved;

	// optional field is set using wifi_config_set_field
	gboolean is_hidden;
	gchar *proxy_address;
	wifi_address_family_e address_family;
	struct _wifi_eap_config *eap_config;
	wifi_error_e last_error;
};

gchar * wifi_config_get_config_id(const gchar *name, wifi_security_type_e security_type);
GSList *wifi_config_get_config_id_list(wifi_dbus *handle);

int wifi_config_get_last_error(wifi_config_h config, wifi_error_e *last_error);

int wifi_save_configurations(wifi_dbus *handle, const gchar *name, const gchar *passphrase, wifi_security_type_e security_type, const gchar *proxy_address, gboolean is_hidden);
int wifi_load_configurations(wifi_dbus *handle, const gchar *config_id, gchar **name, wifi_security_type_e *security_type, gchar **proxy_address, gboolean *is_hidden, wifi_error_e *last_error);
int wifi_configuration_set_field(wifi_dbus *handle, const gchar *config_id, const gchar *key, const gchar *value);
int wifi_configuration_get_passphrase(wifi_dbus *handle, const gchar *config_id, gchar **passphrase);

int wifi_save_eap_configurations(wifi_dbus *handle, const gchar *name, const gchar *passphrase, wifi_security_type_e security_type, const gchar *proxy_address, struct _wifi_eap_config *eap_config, gboolean is_hidden);
int wifi_load_eap_configurations(wifi_dbus *handle, const gchar *config_id, gchar **name, wifi_security_type_e *security_type, gchar **proxy_address, gboolean *is_hidden, struct _wifi_eap_config **eap_config,wifi_error_e *last_error);
wifi_eap_type_e wifi_eap_type_to_int(const gchar *type);
wifi_eap_auth_type_e wifi_eap_auth_type_to_int(const gchar *type);
gchar *wifi_eap_type_to_string(wifi_eap_type_e eap_type);
gchar *wifi_eap_auth_type_to_string(wifi_eap_auth_type_e eap_auth_type);

#endif

