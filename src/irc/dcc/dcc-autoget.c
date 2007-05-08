/*
 dcc-autoget.c : irssi

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
#include "masks.h"
#include "settings.h"
#include "servers.h"

#include "dcc-get.h"

static void sig_dcc_request(GET_DCC_REC *dcc, const char *nickaddr)
{
        struct stat statbuf;
	const char *masks;
        char *str, *file;
        int max_size;

        if (!IS_DCC_GET(dcc)) return;

	/* check if we want to autoget file offer */
	if (!settings_get_bool("dcc_autoget"))
		return;

	/* check for lowports */
	if (dcc->port < 1024 && !settings_get_bool("dcc_autoaccept_lowports"))
                return;

	/* check that autoget masks match */
	masks = settings_get_str("dcc_autoget_masks");
	if (*masks != '\0' &&
	    !masks_match(SERVER(dcc->server), masks, dcc->nick, nickaddr))
		return;

	/* Unless specifically said in dcc_autoget_masks, don't do autogets
	   sent to channels. */
	if (*masks == '\0' && dcc->target != NULL && ischannel(*dcc->target))
		return;

	/* don't autoget files beginning with a dot, if download dir is
	   our home dir (stupid kludge for stupid people) */
	if (*dcc->arg == '.' &&
	    strcmp(settings_get_str("dcc_download_path"), "~") == 0)
		return;

	/* check file size limit, NOTE: it's still possible to send a
	   bogus file size and then just send what ever sized file.. */
        max_size = settings_get_size("dcc_autoget_max_size");
	if (max_size > 0 && (uoff_t)max_size < dcc->size)
                return;

	/* ok. but do we want/need to resume? */
	file = dcc_get_download_path(dcc->arg);
	str = g_strdup_printf(settings_get_bool("dcc_autoresume") &&
			      stat(file, &statbuf) == 0 ?
			      "RESUME %s %s" : "GET %s %s",
			      dcc->nick, dcc->arg);
	signal_emit("command dcc", 2, str, dcc->server);
        g_free(file);
	g_free(str);
}

void dcc_autoget_init(void)
{
	settings_add_bool("dcc", "dcc_autoget", FALSE);
	settings_add_bool("dcc", "dcc_autoaccept_lowports", FALSE);
	settings_add_bool("dcc", "dcc_autoresume", FALSE);
	settings_add_size("dcc", "dcc_autoget_max_size", "0k");
	settings_add_str("dcc", "dcc_autoget_masks", "");

	signal_add_last("dcc request", (SIGNAL_FUNC) sig_dcc_request);
}

void dcc_autoget_deinit(void)
{
	signal_remove("dcc request", (SIGNAL_FUNC) sig_dcc_request);
}
