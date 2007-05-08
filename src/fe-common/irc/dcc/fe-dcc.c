/*
 fe-dcc.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "signals.h"
#include "commands.h"
#include "network.h"
#include "levels.h"
#include "settings.h"

#include "dcc-chat.h"
#include "dcc-file.h"
#include "dcc-get.h"
#include "dcc-send.h"

#include "module-formats.h"
#include "printtext.h"
#include "themes.h"

void fe_dcc_chat_init(void);
void fe_dcc_chat_deinit(void);

void fe_dcc_get_init(void);
void fe_dcc_get_deinit(void);

void fe_dcc_send_init(void);
void fe_dcc_send_deinit(void);

void fe_dcc_server_init(void);
void fe_dcc_server_deinit(void);

char *dcc_get_size_str(uoff_t size)
{
	if (size < 1024)
		return g_strdup_printf("%"PRIuUOFF_T"B", size);
	if (size < 1024*1024)
		return g_strdup_printf("%"PRIuUOFF_T"kB", (size+1023) / 1024);
	return g_strdup_printf("%"PRIuUOFF_T"MB", size / (1024*1024));
}

static void dcc_request(DCC_REC *dcc)
{
	char *service;

	g_return_if_fail(dcc != NULL);

	if (dcc->port < 1024) {
                /* warn about connecting to lowports */
		service = net_getservbyport(dcc->port);

		printformat(dcc->server, NULL, MSGLEVEL_DCC,
			    IRCTXT_DCC_LOWPORT, dcc->port,
			    service != NULL ? service : "unknown");
	}
}

static void dcc_rejected(DCC_REC *dcc)
{
	g_return_if_fail(dcc != NULL);

	printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CLOSE,
		    dcc_type2str(dcc->type), dcc->nick, dcc->arg);
}

static void dcc_request_send(DCC_REC *dcc)
{
	g_return_if_fail(dcc != NULL);

	printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_REQUEST_SEND,
		    dcc_type2str(dcc->type), dcc->nick, dcc->arg);
}

static void dcc_error_connect(DCC_REC *dcc)
{
	g_return_if_fail(dcc != NULL);

        printformat(dcc->server, NULL, MSGLEVEL_DCC,
                    IRCTXT_DCC_CONNECT_ERROR, dcc->addrstr, dcc->port);
}

static void dcc_error_unknown_type(const char *type)
{
	g_return_if_fail(type != NULL);

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_UNKNOWN_TYPE, type);
}

void dcc_list_print_file(FILE_DCC_REC *dcc)
{
	time_t going, eta;
	char *transfd_str, *size_str, etastr[20];
	uoff_t bps;

	going = time(NULL) - dcc->starttime;
	if (going <= 0) going = 1;

	transfd_str = dcc_get_size_str(dcc->transfd);
	size_str = dcc_get_size_str(dcc->size);

	bps = (dcc->transfd-dcc->skipped) / going;
	if (bps == 0) {
		strcpy(etastr, "(stalled)");
	} else {
		eta = (dcc->size - dcc->transfd) / bps;
		g_snprintf(etastr, sizeof(etastr), "%02d:%02d:%02d",
			   (int)(eta/3600), (int)((eta/60)%60), (int)(eta%60));
	}

	printformat(NULL, NULL, MSGLEVEL_DCC,
		    IRCTXT_DCC_LIST_LINE_FILE,
		    dcc->nick, dcc_type2str(dcc->type),
		    transfd_str, size_str,
		    dcc->size == 0 ? 0 : (int)((double)dcc->transfd/(double)dcc->size*100.0),
		    (double)bps/1024.0, dcc->arg, etastr);

	g_free(transfd_str);
	g_free(size_str);
}

static void cmd_dcc_list(const char *data)
{
	GSList *tmp;

	g_return_if_fail(data != NULL);

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_LIST_HEADER);
	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next)
		signal_emit("dcc list print", 1, tmp->data);
	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_LIST_FOOTER);
}

static void cmd_dcc(const char *data)
{
	if (*data == '\0') {
		cmd_dcc_list(data);
		signal_stop();
	}
}

void fe_irc_dcc_init(void)
{
	fe_dcc_chat_init();
	fe_dcc_get_init();
	fe_dcc_send_init();
	fe_dcc_server_init();

	signal_add("dcc request", (SIGNAL_FUNC) dcc_request);
	signal_add("dcc rejected", (SIGNAL_FUNC) dcc_rejected);
	signal_add("dcc request send", (SIGNAL_FUNC) dcc_request_send);
	signal_add("dcc error connect", (SIGNAL_FUNC) dcc_error_connect);
	signal_add("dcc error unknown type", (SIGNAL_FUNC) dcc_error_unknown_type);
	command_bind("dcc", NULL, (SIGNAL_FUNC) cmd_dcc);
	command_bind("dcc list", NULL, (SIGNAL_FUNC) cmd_dcc_list);

	theme_register(fecommon_irc_dcc_formats);
	settings_check();
	module_register("dcc", "fe-irc");
}

void fe_irc_dcc_deinit(void)
{
	fe_dcc_chat_deinit();
	fe_dcc_get_deinit();
	fe_dcc_send_deinit();
	fe_dcc_server_deinit();

	theme_unregister();

	signal_remove("dcc request", (SIGNAL_FUNC) dcc_request);
	signal_remove("dcc rejected", (SIGNAL_FUNC) dcc_rejected);
	signal_remove("dcc request send", (SIGNAL_FUNC) dcc_request_send);
	signal_remove("dcc error connect", (SIGNAL_FUNC) dcc_error_connect);
	signal_remove("dcc error unknown type", (SIGNAL_FUNC) dcc_error_unknown_type);
	command_unbind("dcc", (SIGNAL_FUNC) cmd_dcc);
	command_unbind("dcc list", (SIGNAL_FUNC) cmd_dcc_list);
}
