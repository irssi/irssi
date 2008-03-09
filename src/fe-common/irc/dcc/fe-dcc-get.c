/*
 fe-dcc-get.c : irssi

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
#include "levels.h"

#include "irc.h"
#include "dcc-file.h"
#include "dcc-get.h"

#include "module-formats.h"
#include "printtext.h"

#include "fe-dcc.h"

static void dcc_request(GET_DCC_REC *dcc)
{
	char *sizestr;

        if (!IS_DCC_GET(dcc)) return;

	sizestr = dcc_get_size_str(dcc->size);

	printformat(dcc->server, NULL, MSGLEVEL_DCC,
		    ischannel(*dcc->target) ? IRCTXT_DCC_SEND_CHANNEL :
		    IRCTXT_DCC_SEND, dcc->nick, dcc->addrstr,
		    dcc->port, dcc->arg, sizestr, dcc->target);

	g_free(sizestr);
}

static void dcc_connected(GET_DCC_REC *dcc)
{
        if (!IS_DCC_GET(dcc)) return;

	printformat(dcc->server, NULL, MSGLEVEL_DCC, IRCTXT_DCC_GET_CONNECTED,
		    dcc->arg, dcc->nick, dcc->addrstr, dcc->port);
}

static void dcc_closed(GET_DCC_REC *dcc)
{
	char *sizestr, timestr[20];
	double kbs;
	time_t secs;

        if (!IS_DCC_GET(dcc)) return;

	secs = dcc->starttime == 0 ? -1 : time(NULL)-dcc->starttime;
	kbs = (double) (dcc->transfd-dcc->skipped) /
		(secs == 0 ? 1 : secs) / 1024.0;

	sizestr = dcc_get_size_str(dcc->transfd);
	g_snprintf(timestr, sizeof(timestr), "%02d:%02d:%02d",
		   (int)(secs/3600), (int)((secs/60)%60), (int)(secs%60));

	if (secs == -1) {
		/* aborted */
		printformat(dcc->server, NULL, MSGLEVEL_DCC,
			    IRCTXT_DCC_GET_ABORTED, dcc->arg, dcc->nick);
	} else {
		printformat(dcc->server, NULL, MSGLEVEL_DCC,
			    IRCTXT_DCC_GET_COMPLETE, dcc->arg, sizestr,
			    dcc->nick, timestr, kbs);
	}

	g_free(sizestr);
}

static void dcc_error_file_create(GET_DCC_REC *dcc, const char *fname,
				  const char *error)
{
	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_CANT_CREATE,
		    fname, error);
}


static void dcc_error_get_not_found(const char *nick)
{
	g_return_if_fail(nick != NULL);

	printformat(NULL, NULL, MSGLEVEL_DCC, IRCTXT_DCC_GET_NOT_FOUND, nick);
}

static void dcc_error_close_not_found(const char *type, const char *nick,
				      const char *fname)
{
	g_return_if_fail(type != NULL);
	g_return_if_fail(nick != NULL);
	g_return_if_fail(fname != NULL);
	if (g_ascii_strcasecmp(type, "GET") != 0) return;

	if (fname == '\0') fname = "(ANY)";
	printformat(NULL, NULL, MSGLEVEL_DCC,
		    IRCTXT_DCC_GET_NOT_FOUND, nick, fname);
}

static void dcc_error_write(GET_DCC_REC *dcc, const char *error)
{
	printformat(NULL, NULL, MSGLEVEL_DCC,
		    IRCTXT_DCC_GET_WRITE_ERROR, dcc->file, error);
}

static void sig_dcc_list_print(GET_DCC_REC *dcc)
{
	if (IS_DCC_GET(dcc))
		dcc_list_print_file((FILE_DCC_REC *) dcc);
}

void fe_dcc_get_init(void)
{
	signal_add("dcc request", (SIGNAL_FUNC) dcc_request);
	signal_add("dcc connected", (SIGNAL_FUNC) dcc_connected);
	signal_add("dcc closed", (SIGNAL_FUNC) dcc_closed);
	signal_add("dcc error file create", (SIGNAL_FUNC) dcc_error_file_create);
	signal_add("dcc error get not found", (SIGNAL_FUNC) dcc_error_get_not_found);
	signal_add("dcc error close not found", (SIGNAL_FUNC) dcc_error_close_not_found);
	signal_add("dcc error write", (SIGNAL_FUNC) dcc_error_write);
        signal_add("dcc list print", (SIGNAL_FUNC) sig_dcc_list_print);
}

void fe_dcc_get_deinit(void)
{
	signal_remove("dcc request", (SIGNAL_FUNC) dcc_request);
	signal_remove("dcc connected", (SIGNAL_FUNC) dcc_connected);
	signal_remove("dcc closed", (SIGNAL_FUNC) dcc_closed);
	signal_remove("dcc error file create", (SIGNAL_FUNC) dcc_error_file_create);
	signal_remove("dcc error get not found", (SIGNAL_FUNC) dcc_error_get_not_found);
	signal_remove("dcc error close not found", (SIGNAL_FUNC) dcc_error_close_not_found);
	signal_remove("dcc error write", (SIGNAL_FUNC) dcc_error_write);
        signal_remove("dcc list print", (SIGNAL_FUNC) sig_dcc_list_print);
}
