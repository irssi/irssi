/*
 fe-expandos.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include <irssip/src/core/expandos.h>
#include <irssip/src/fe-common/core/fe-windows.h>
#include <irssip/src/core/settings.h>

/* Nick column context variables */
static char *current_nick = NULL;
static char *current_mode = NULL;
static gboolean nick_context_valid = FALSE;

/* Window ref# */
static char *expando_winref(SERVER_REC *server, void *item, int *free_ret)
{
	if (active_win == NULL)
		return "";

        *free_ret = TRUE;
	return g_strdup_printf("%d", active_win->refnum);
}

/* Window name */
static char *expando_winname(SERVER_REC *server, void *item, int *free_ret)
{
	if (active_win == NULL)
		return "";

	return active_win->name;
}

/* Nick column aligned - returns padded string with mode and nick */
static char *expando_nickaligned(SERVER_REC *server, void *item, int *free_ret)
{
	int width, mode_len, nick_len, available_for_nick;
	const char *mode;
	char *result;

	if (!settings_get_bool("nick_column_enabled") || !nick_context_valid || !current_nick) {
		return "";
	}

	width = settings_get_int("nick_column_width");
	mode = current_mode ? current_mode : "";
	mode_len = strlen(mode);
	nick_len = strlen(current_nick);

	/* Always reserve 1 space for mode (even if empty) */
	available_for_nick = width - 1;

	if (mode_len == 0) {
		/* No mode - use space + nick */
		if (nick_len <= available_for_nick) {
			/* Nick fits - pad from left */
			int padding = width - 1 - nick_len; /* -1 for space */
			result = g_strdup_printf("%*s %s", padding, "", current_nick);
		} else {
			/* Nick too long - truncate with >> */
			result = g_strdup_printf(" %.*s>>", available_for_nick - 2, current_nick);
		}
	} else {
		/* Has mode */
		int total_len = mode_len + nick_len;
		if (total_len <= width) {
			/* Mode + nick fits - pad from left */
			int padding = width - total_len;
			result = g_strdup_printf("%*s%s%s", padding, "", mode, current_nick);
		} else {
			/* Too long - truncate nick with >> */
			int available_for_nick_with_mode = width - mode_len - 2; /* -2 for >> */
			if (available_for_nick_with_mode > 0) {
				result = g_strdup_printf("%s%.*s>>", mode, available_for_nick_with_mode, current_nick);
			} else {
				/* Mode itself too long */
				result = g_strdup_printf("%.*s>>", width - 2, mode);
			}
		}
	}

	/* Debug output */
	if (settings_get_bool("debug_nick_column")) {
		printf("DEBUG nickaligned: nick='%s', mode='%s', width=%d, result='%s'\n",
		       current_nick, mode, width, result);
	}

	*free_ret = TRUE;
	return result;
}

/* Update nick context for expandos */
void update_nick_context(const char *nick, const char *mode)
{
	g_free(current_nick);
	g_free(current_mode);
	current_nick = g_strdup(nick);
	current_mode = g_strdup(mode ? mode : "");
	nick_context_valid = TRUE;
}

/* Clear nick context */
void clear_nick_context(void)
{
	nick_context_valid = FALSE;
}

void fe_expandos_init(void)
{
	expando_create("winref", expando_winref,
		       "window changed", EXPANDO_ARG_NONE,
		       "window refnum changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("winname", expando_winname,
		       "window changed", EXPANDO_ARG_NONE,
		       "window name changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("nickaligned", expando_nickaligned,
		       "message public", EXPANDO_ARG_NONE,
		       "message own_public", EXPANDO_ARG_NONE, NULL);
}

void fe_expandos_deinit(void)
{
	expando_destroy("winref", expando_winref);
	expando_destroy("winname", expando_winname);
	expando_destroy("nickaligned", expando_nickaligned);
}
