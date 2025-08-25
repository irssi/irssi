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
#include <irssi/src/core/expandos.h>
#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/core/levels.h>

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

/* Count only valid nick characters (ignore color codes) */
static int count_nick_chars(const char *str)
{
	int count = 0;
	if (!str)
		return 0;

	for (const char *p = str; *p; p++) {
		/* Alfanumeryczne */
		if (isalnum(*p)) {
			count++;
		}
		/* Specjalne znaki nicka - zgodnie z isnickchar z fe-messages.c */
		else if (*p == '`' || *p == '-' || *p == '_' || *p == '[' || *p == ']' ||
		         *p == '{' || *p == '}' || *p == '|' || *p == '\\' || *p == '^') {
			count++;
		}
		/* Ignoruje kody kolorów %B %N %Y %n itp. */
	}
	return count;
}

/* Nick column align - returns only padding spaces */
static char *expando_nickalign(SERVER_REC *server, void *item, int *free_ret)
{
	int width, mode_chars, nick_chars, total_chars, padding;
	const char *mode;

	/* Gdy wyłączone - zwróć pusty string */
	if (!settings_get_bool("nick_column_enabled")) {
		return "";
	}

	if (!nick_context_valid || !current_nick) {
		return "";
	}

	width = settings_get_int("nick_column_width");
	mode = current_mode ? current_mode : "";

	/* Zawsze 1 miejsce na mode (nawet spacja) */
	mode_chars = strlen(mode) > 0 ? strlen(mode) : 1;
	nick_chars = count_nick_chars(current_nick);
	total_chars = mode_chars + nick_chars;

	if (total_chars > width) {
		padding = 0;
	} else {
		padding = width - total_chars;
	}

	*free_ret = TRUE;
	return g_strnfill(padding, ' ');
}

/* Nick truncated - returns truncated nick with >> indicator */
static char *expando_nicktrunc(SERVER_REC *server, void *item, int *free_ret)
{
	int width, mode_chars, nick_chars, total_chars;
	const char *mode;
	char *result;

	/* Gdy wyłączone - zwróć oryginalny nick */
	if (!settings_get_bool("nick_column_enabled")) {
		return current_nick ? current_nick : "";
	}

	if (!nick_context_valid || !current_nick) {
		return current_nick ? current_nick : "";
	}

	width = settings_get_int("nick_column_width");
	mode = current_mode ? current_mode : "";

	/* Zawsze 1 miejsce na mode (nawet spacja) */
	mode_chars = strlen(mode) > 0 ? strlen(mode) : 1;
	nick_chars = count_nick_chars(current_nick);
	total_chars = mode_chars + nick_chars;

	if (total_chars > width) {
		/* Nick za długi - przytnij z >> */
		int available_for_nick = width - mode_chars - 2; /* -2 dla >> */
		if (available_for_nick > 0) {
			/* Przytnij nick i dodaj >> */
			result = g_strdup_printf("%.*s>>", available_for_nick, current_nick);

		} else {
			/* Mode sam za długi */
			result = g_strdup(">>");
		}
		*free_ret = TRUE;
		return result;
	} else {
		/* Nick się zmieści - zwróć oryginalny */

		return current_nick;
	}
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
	expando_create("winref", expando_winref, "window changed", EXPANDO_ARG_NONE,
	               "window refnum changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("winname", expando_winname, "window changed", EXPANDO_ARG_NONE,
	               "window name changed", EXPANDO_ARG_WINDOW, NULL);
	expando_create("nickalign", expando_nickalign, "message public", EXPANDO_ARG_NONE,
	               "message own_public", EXPANDO_ARG_NONE, NULL);
	expando_create("nicktrunc", expando_nicktrunc, "message public", EXPANDO_ARG_NONE,
	               "message own_public", EXPANDO_ARG_NONE, NULL);
}

void fe_expandos_deinit(void)
{
	expando_destroy("winref", expando_winref);
	expando_destroy("winname", expando_winname);
	expando_destroy("nickalign", expando_nickalign);
	expando_destroy("nicktrunc", expando_nicktrunc);
}
