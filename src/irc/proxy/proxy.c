/*
 sample.c : sample plugin for irssi

    Copyright (C) 1999 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "proxy.h"
#include "levels.h"
#include "fe-common/core/printtext.h"
#include "servers.h"
#include "net-sendbuffer.h"

#include "lib-config/iconfig.h"
#include "settings.h"

PLUGIN_DATA *proxy_data;
MODULE_REC *plug;



gchar *plugin_description(void)
{
    return "IRC proxy plugin";
}

/*gint plugin_version(void)
{
    return PLUGIN_LAYER_VERSION;
}
*/

void proxy_settings_init(void)
{
	settings_add_str("proxy", "proxy_listen_addr", "localhost");
	settings_add_int("proxy", "proxy_listen_port", 2777);
	settings_add_str("proxy", "proxy_listen_password", "");
}



/* If we call plugin_deinit() in this code, it doesn't necessarily point to
   _THIS_ module's plugin_deinit() but instead some other module's.. So,
   we create static deinit() function which should be used.. */
static void deinit(/*MODULE_REC *plugin*/)
{
	plugin_proxy_listen_deinit(proxy_data);
}


void proxy_deinit(/*MODULE_REC *plugin*/)
{
  deinit(/*plugin*/);
}

gboolean proxy_init(void)
{

    gchar ipaddr[MAX_IP_LEN];

    const char *password;
    const char *addr;
    int port;

    proxy_settings_init();

    proxy_data = g_new0(PLUGIN_DATA, 1);
    password = settings_get_str("proxy_listen_password");
    addr = settings_get_str("proxy_listen_addr");
    port = settings_get_int("proxy_listen_port");

    plug = module_find("proxy");
    proxy_data->plugin = plug;

    if (*password != '\0')
    {
       	/* args = password */
       	proxy_data->password = g_strdup(password);
    }
    if (*addr != '\0')
    {
       	/* specify ip address to listen */
       	net_host2ip(addr, &proxy_data->ip);
    }
    if (port != 0)
    {
       	/* specify port to use */
       	proxy_data->port = port;
    }
    
    if (proxy_data->password == NULL)
    {
    	/* no password - bad idea! */
    	printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE, "Warning!! Password not specified, everyone can use this proxy! Use /set proxy_listen_password <password> to set it");
    }

    if (servers == NULL)
    {
    	/* FIXME: not good */
    	printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "You need to specify IP address to listen with /set proxy_listen_addr <address>");
    	deinit();
    	return FALSE;
    }
    else
    {
    	SERVER_REC *server;

    	server = servers->data;
    	if (net_getsockname(net_sendbuffer_handle(server->handle), &proxy_data->ip, NULL))
    	{
	    deinit();
	    return FALSE;
	}
    }

    net_ip2host(&proxy_data->ip, ipaddr);
    printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE, "Proxy plugin loaded - listening in interface %s port %d", ipaddr, proxy_data->port);

    plugin_proxy_listen_init(proxy_data);

    proxy_data->loaded = TRUE;
    return TRUE;
}
