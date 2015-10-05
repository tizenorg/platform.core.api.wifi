#ifndef __WIFI_DBUS_H__
#define __WIFI_DBUS_H__

#include <gio/gio.h>

#define DBUS_REPLY_TIMEOUT      (120 * 1000)

#define NETCONFIG_SERVICE                                       "net.netconfig"
#define NETCONFIG_IWIFI                                         "net.netconfig.wifi"
#define NETCONFIG_INETWORK                                      "net.netconfig.network"
#define NETCONFIG_ISTATISTICS                           "net.netconfig.network_statistics"

#define NETCONFIG_WIFI_PATH                             "/net/netconfig/wifi"
#define NETCONFIG_NETWORK_PATH                  "/net/netconfig/network"
#define NETCONFIG_STATISTICS_PATH                       "/net/netconfig/network_statistics"

struct _wifi_dbus {
	GDBusConnection *dbus_conn;
	GCancellable *ca;
};

typedef struct _wifi_dbus wifi_dbus;

int wifi_dbus_init(wifi_dbus **handle);
int wifi_dbus_deinit(wifi_dbus *handle);

#endif
