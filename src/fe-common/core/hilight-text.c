/*
 hilight-text.c : irssi

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
#include "commands.h"
#include "misc.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "levels.h"
#include "server.h"

#include "hilight-text.h"

#define DEFAULT_HILIGHT_CHECK_LEVEL \
	(MSGLEVEL_PUBLIC | MSGLEVEL_MSGS | MSGLEVEL_NOTICES | MSGLEVEL_ACTIONS)

static int hilight_next;
GSList *hilights;

static void hilight_add_config(HILIGHT_REC *rec)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("(hilights", TRUE);
	node = config_node_section(node, NULL, NODE_TYPE_BLOCK);

        config_node_set_str(node, "text", rec->text);
        if (rec->level > 0) config_node_set_int(node, "level", rec->level);
        if (rec->color) config_node_set_str(node, "color", rec->color);
        if (rec->nickmask) config_node_set_bool(node, "nickmask", TRUE);
        if (rec->fullword) config_node_set_bool(node, "fullword", TRUE);
        if (rec->regexp) config_node_set_bool(node, "regexp", TRUE);

	if (rec->channels != NULL && *rec->channels != NULL) {
		node = config_node_section(node, "channels", NODE_TYPE_LIST);
		config_node_add_list(node, rec->channels);
	}
}

static void hilight_remove_config(HILIGHT_REC *rec)
{
	CONFIG_NODE *node;

	node = iconfig_node_traverse("hilights", FALSE);
	if (node != NULL) config_node_list_remove(node, g_slist_index(hilights, rec));
}

static void hilight_destroy(HILIGHT_REC *rec)
{
	g_free(rec->text);
	g_free_not_null(rec->color);
	g_free(rec);
}

static void hilights_destroy_all(void)
{
	g_slist_foreach(hilights, (GFunc) hilight_destroy, NULL);
	g_slist_free(hilights);
	hilights = NULL;
}

static void hilight_remove(HILIGHT_REC *rec)
{
	hilight_remove_config(rec);
	hilights = g_slist_remove(hilights, rec);
	hilight_destroy(rec);
}

static HILIGHT_REC *hilight_find(const char *text, char **channels)
{
	GSList *tmp;
	char **chan;

	g_return_val_if_fail(text != NULL, NULL);

	for (tmp = hilights; tmp != NULL; tmp = tmp->next) {
		HILIGHT_REC *rec = tmp->data;

		if (g_strcasecmp(rec->text, text) != 0)
			continue;

		if ((channels == NULL && rec->channels == NULL))
			return rec; /* no channels - ok */

		if (channels != NULL && strcmp(*channels, "*") == 0)
			return rec; /* ignore channels */

		if (channels == NULL || rec->channels == NULL)
			continue; /* other doesn't have channels */

		if (strarray_length(channels) != strarray_length(rec->channels))
			continue; /* different amount of channels */

		/* check that channels match */
		for (chan = channels; *chan != NULL; chan++) {
			if (strarray_find(rec->channels, *chan) == -1)
                                break;
		}

		if (*chan == NULL)
			return rec; /* channels ok */
	}

	return NULL;
}

static void sig_print_text(SERVER_REC *server, const char *channel, gpointer level, const char *str)
{
	if (hilight_next) {
		hilight_next = FALSE;
		signal_stop();
	}
}

static void sig_print_text_stripped(SERVER_REC *server, const char *channel, gpointer plevel, const char *str)
{
	GSList *tmp;
        char *color, *newstr;
	int len, level, best_match;

	g_return_if_fail(str != NULL);

	level = GPOINTER_TO_INT(plevel);
	if (level & (MSGLEVEL_NOHILIGHT|MSGLEVEL_HILIGHT)) return;

	color = NULL; best_match = 0;
	for (tmp = hilights; tmp != NULL; tmp = tmp->next) {
		HILIGHT_REC *rec = tmp->data;

		if (rec->nickmask)
			continue;
		if ((level & (rec->level > 0 ? rec->level : DEFAULT_HILIGHT_CHECK_LEVEL)) == 0)
                        continue;
		if (rec->channels != NULL && !strarray_find(rec->channels, channel))
			continue;
		if (rec->regexp) {
			if (!regexp_match(str, rec->text))
				continue;
		} else if (rec->fullword) {
			if (stristr_full(str, rec->text) == NULL)
				continue;
		} else {
			if (stristr(str, rec->text) == NULL)
				continue;
		}

		len = strlen(rec->text);
		if (best_match < len) {
			best_match = len;
			color = rec->color;
		}
	}

	if (best_match > 0) {
		hilight_next = FALSE;

		if (color == NULL) color = "\00316";
		newstr = g_strconcat(isdigit(*color) ? "\003" : "", color, str, NULL);
		signal_emit("print text", 4, server, channel, GINT_TO_POINTER(level | MSGLEVEL_HILIGHT), newstr);
		g_free(newstr);

		hilight_next = TRUE;
	}
}

static void read_hilight_config(void)
{
	CONFIG_NODE *node;
	HILIGHT_REC *rec;
	GSList *tmp;
	char *text, *color;

	hilights_destroy_all();

	node = iconfig_node_traverse("hilights", FALSE);
	if (node == NULL) return;

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		node = tmp->data;

		if (node->type != NODE_TYPE_BLOCK)
			continue;

		text = config_node_get_str(node, "text", NULL);
		if (text == NULL || *text == '\0')
			continue;

		rec = g_new0(HILIGHT_REC, 1);
		hilights = g_slist_append(hilights, rec);

		color = config_node_get_str(node, "color", NULL);

		rec->text = g_strdup(text);
		rec->color = color == NULL || *color == '\0' ? NULL :
			g_strdup(color);
		rec->level = config_node_get_int(node, "level", 0);
		rec->nickmask = config_node_get_bool(node, "nickmask", FALSE);
		rec->fullword = config_node_get_bool(node, "fullword", FALSE);
		rec->regexp = config_node_get_bool(node, "regexp", FALSE);

		node = config_node_section(node, "channels", -1);
		if (node != NULL) rec->channels = config_node_get_list(node);
	}
}

static void hilight_print(int index, HILIGHT_REC *rec)
{
	char *chans, *levelstr;

	chans = rec->channels == NULL ? NULL :
		g_strjoinv(",", rec->channels);
	levelstr = rec->level == 0 ? NULL :
		bits2level(rec->level);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    IRCTXT_HILIGHT_LINE, index, rec->text,
		    chans != NULL ? chans : "",
		    levelstr != NULL ? levelstr : "",
		    rec->nickmask ? " -nick" : "",
		    rec->fullword ? " -word" : "",
		    rec->regexp ? " -regexp" : "");
	g_free_not_null(chans);
	g_free_not_null(levelstr);
}

static void cmd_hilight_show(void)
{
	GSList *tmp;
	int index;

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_HILIGHT_HEADER);
	index = 1;
	for (tmp = hilights; tmp != NULL; tmp = tmp->next, index++) {
		HILIGHT_REC *rec = tmp->data;

		hilight_print(index, rec);
	}
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, IRCTXT_HILIGHT_FOOTER);
}

static void cmd_hilight(const char *data)
{
	/* /HILIGHT [-nick | -regexp | -word] [-color <color>] [-level <level>] [-channels <channels>] <text> */
	char *params, *args, *colorarg, *levelarg, *chanarg, *text;
	char **channels;
	HILIGHT_REC *rec;

	g_return_if_fail(data != NULL);

	if (*data == '\0') {
		cmd_hilight_show();
		return;
	}

	args = "color level channels";
	params = cmd_get_params(data, 5 | PARAM_FLAG_MULTIARGS | PARAM_FLAG_GETREST,
				&args, &colorarg, &levelarg, &chanarg, &text);
	if (*text == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	channels = *chanarg == '\0' ? NULL :
		g_strsplit(replace_chars(chanarg, ',', ' '), " ", -1);

	rec = hilight_find(text, channels);
	if (rec == NULL) {
		rec = g_new0(HILIGHT_REC, 1);

		rec->text = g_strdup(text);
		rec->channels = channels;
	} else {
                g_free_and_null(rec->color);
		g_strfreev(channels);

                hilight_remove_config(rec);
		hilights = g_slist_remove(hilights, rec);
	}

	hilights = g_slist_append(hilights, rec);
	rec->nickmask = stristr(args, "-nick") != NULL;
	rec->fullword = stristr(args, "-word") != NULL;
	rec->regexp = stristr(args, "-regexp") != NULL;

	rec->level = level2bits(replace_chars(levelarg, ',', ' '));
	if (*colorarg != '\0') rec->color = g_strdup(colorarg);

	hilight_print(g_slist_index(hilights, rec)+1, rec);

	hilight_add_config(rec);
	g_free(params);
}

static void cmd_dehilight(const char *data)
{
	HILIGHT_REC *rec;
	GSList *tmp;

	if (is_numeric(data, ' ')) {
		/* with index number */
		tmp = g_slist_nth(hilights, atol(data)-1);
		rec = tmp == NULL ? NULL : tmp->data;
	} else {
		/* with mask */
		char *chans[2] = { "*", NULL };
                rec = hilight_find(data, chans);
	}

	if (rec == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_HILIGHT_NOT_FOUND, data);
	else
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_HILIGHT_REMOVED, rec->text);
	hilight_remove(rec);
}

void hilight_text_init(void)
{
	hilight_next = FALSE;

	read_hilight_config();

	signal_add_first("print text", (SIGNAL_FUNC) sig_print_text);
	signal_add_first("print text stripped", (SIGNAL_FUNC) sig_print_text_stripped);
        signal_add("setup reread", (SIGNAL_FUNC) read_hilight_config);
	command_bind("hilight", NULL, (SIGNAL_FUNC) cmd_hilight);
	command_bind("dehilight", NULL, (SIGNAL_FUNC) cmd_dehilight);
}

void hilight_text_deinit(void)
{
	hilights_destroy_all();

	signal_remove("print text", (SIGNAL_FUNC) sig_print_text);
	signal_remove("print text stripped", (SIGNAL_FUNC) sig_print_text_stripped);
        signal_remove("setup reread", (SIGNAL_FUNC) read_hilight_config);
	command_unbind("hilight", (SIGNAL_FUNC) cmd_hilight);
	command_unbind("dehilight", (SIGNAL_FUNC) cmd_dehilight);
}
