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

#include "wifi.h"
#include "wifi_dbus_private.h"
#include "net_wifi_private.h"

int wifi_dbus_init(wifi_dbus **handle)
{
	struct _wifi_dbus *h;
	GError *error = NULL;

	h = g_new0(struct _wifi_dbus, 1);
	if (!h) {
		WIFI_LOG(WIFI_ERROR, "_wifi_dbus alloc error"); //LCOV_EXCL_LINE
		return WIFI_ERROR_OUT_OF_MEMORY; //LCOV_EXCL_LINE
	}

#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init();
#endif

	h->dbus_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!h->dbus_conn) {
		WIFI_LOG(WIFI_ERROR, "dbus connection get failed: %s", error->message); //LCOV_EXCL_LINE
		g_error_free(error); //LCOV_EXCL_LINE
		g_free(h); //LCOV_EXCL_LINE
		return WIFI_ERROR_OUT_OF_MEMORY; //LCOV_EXCL_LINE
	}
	h->ca = g_cancellable_new();

	*handle = (wifi_dbus *)h;

	return WIFI_ERROR_NONE;
}

int wifi_dbus_deinit(wifi_dbus *handle)
{
	g_return_val_if_fail(handle != NULL, WIFI_ERROR_INVALID_PARAMETER);

	g_cancellable_cancel(handle->ca);
	g_object_unref(handle->ca);
	g_object_unref(handle->dbus_conn);

	memset(handle, 0, sizeof(struct _wifi_dbus));
	g_free(handle);

	return WIFI_ERROR_NONE;
}
