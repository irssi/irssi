/*
 fe-common-irc.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "args.h"
#include "misc.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "server-setup.h"

#include "themes.h"
#include "completion.h"

void fe_irc_modules_init(void);
void fe_irc_modules_deinit(void);

void fe_channels_init(void);
void fe_channels_deinit(void);

void fe_irc_commands_init(void);
void fe_irc_commands_deinit(void);

void fe_ircnet_init(void);
void fe_ircnet_deinit(void);

void fe_irc_server_init(void);
void fe_irc_server_deinit(void);

void fe_ctcp_init(void);
void fe_ctcp_deinit(void);

void fe_events_init(void);
void fe_events_deinit(void);

void fe_events_numeric_init(void);
void fe_events_numeric_deinit(void);

void fe_ignore_init(void);
void fe_ignore_deinit(void);

void fe_query_init(void);
void fe_query_deinit(void);

void irc_completion_init(void);
void irc_completion_deinit(void);

void fe_netsplit_init(void);
void fe_netsplit_deinit(void);

void fe_netjoin_init(void);
void fe_netjoin_deinit(void);

void irc_hilight_text_init(void);
void irc_hilight_text_deinit(void);

void irc_window_activity_init(void);
void irc_window_activity_deinit(void);

static char *autocon_server;
static char *autocon_password;
static int autocon_port;
static int no_autoconnect;
static char *cmdline_nick;
static char *cmdline_hostname;

void fe_common_irc_init(void)
{
	static struct poptOption options[] = {
		{ "connect", 'c', POPT_ARG_STRING, &autocon_server, 0, N_("Automatically connect to server/ircnet"), N_("SERVER") },
		{ "password", 'w', POPT_ARG_STRING, &autocon_password, 0, N_("Autoconnect password"), N_("SERVER") },
		{ "port", 'p', POPT_ARG_INT, &autocon_port, 0, N_("Autoconnect port"), N_("PORT") },
		{ "noconnect", '!', POPT_ARG_NONE, &no_autoconnect, 0, N_("Disable autoconnecting"), NULL },
		{ "nick", 'n', POPT_ARG_STRING, &cmdline_nick, 0, N_("Specify nick to use"), NULL },
		{ "hostname", 'h', POPT_ARG_STRING, &cmdline_hostname, 0, N_("Specify host name to use"), NULL },
		{ NULL, '\0', 0, NULL }
	};

	autocon_server = NULL;
	autocon_password = NULL;
	autocon_port = 6667;
	no_autoconnect = FALSE;
	cmdline_nick = NULL;
	cmdline_hostname = NULL;
	args_register(options);

	settings_add_str("lookandfeel", "beep_on_msg", "");
	settings_add_bool("lookandfeel", "beep_when_away", TRUE);
	settings_add_bool("lookandfeel", "show_away_once", TRUE);
	settings_add_bool("lookandfeel", "show_quit_once", FALSE);
	settings_add_bool("lookandfeel", "print_active_channel", FALSE);

	theme_register(fecommon_irc_formats);

	fe_channels_init();
	fe_irc_commands_init();
	fe_ircnet_init();
	fe_irc_server_init();
	fe_ctcp_init();
	fe_events_init();
	fe_events_numeric_init();
	fe_ignore_init();
	fe_netsplit_init();
	fe_netjoin_init();
	fe_query_init();
	irc_completion_init();
	irc_hilight_text_init();
	irc_window_activity_init();

	fe_irc_modules_init();
}

void fe_common_irc_deinit(void)
{
	fe_irc_modules_deinit();

	fe_channels_deinit();
	fe_irc_commands_deinit();
	fe_ircnet_deinit();
	fe_irc_server_deinit();
	fe_ctcp_deinit();
	fe_events_deinit();
	fe_events_numeric_deinit();
	fe_ignore_deinit();
	fe_netsplit_deinit();
	fe_netjoin_deinit();
	fe_query_deinit();
	irc_completion_deinit();
	irc_hilight_text_deinit();
	irc_window_activity_deinit();

	theme_unregister();
}

void fe_common_irc_finish_init(void)
{
	GSList *tmp, *ircnets;
	char *str;

	if (cmdline_nick != NULL) {
		/* override nick found from setup */
		iconfig_set_str("settings", "default_nick", cmdline_nick);
	}

	if (cmdline_hostname != NULL) {
		/* override host name found from setup */
		iconfig_set_str("settings", "hostname", cmdline_hostname);
	}

	if (autocon_server != NULL) {
		/* connect to specified server */
		str = g_strdup_printf(autocon_password == NULL ? "%s %d" : "%s %d %s",
				      autocon_server, autocon_port, autocon_password);
		signal_emit("command connect", 1, str);
		g_free(str);
		return;
	}

	if (no_autoconnect) {
		/* don't autoconnect */
		return;
	}

	/* connect to autoconnect servers */
	ircnets = NULL;
	for (tmp = setupservers; tmp != NULL; tmp = tmp->next) {
		SETUP_SERVER_REC *rec = tmp->data;

		if (rec->autoconnect && (rec->ircnet == NULL || *rec->ircnet == '\0' ||
					 gslist_find_icase_string(ircnets, rec->ircnet) == NULL)) {
			if (rec->ircnet != NULL && *rec->ircnet != '\0')
				ircnets = g_slist_append(ircnets, rec->ircnet);

			str = g_strdup_printf("%s %d", rec->address, rec->port);
			signal_emit("command connect", 1, str);
			g_free(str);
		}
	}

	g_slist_free(ircnets);
}
