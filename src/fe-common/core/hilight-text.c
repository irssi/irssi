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

#define DEFAULT_HILIGHT_LEVEL \
	(MSGLEVEL_PUBLIC | MSGLEVEL_MSGS | \
	MSGLEVEL_ACTIONS | MSGLEVEL_DCCMSGS)

static int hilight_next;
GSList *hilights;

static void hilight_add_config(HILIGHT_REC *rec)
{
	CONFIG_NODE *node;

	g_return_if_fail(rec != NULL);

	node = iconfig_node_traverse("(hilights", TRUE);
	node = config_node_section(node, NULL, NODE_TYPE_BLOCK);

        iconfig_node_set_str(node, "text", rec->text);
        if (rec->level > 0) config_node_set_int(node, "level", rec->level);
        if (rec->color) iconfig_node_set_str(node, "color", rec->color);
        if (rec->nick) config_node_set_bool(node, "nick", TRUE);
        if (rec->nickmask) config_node_set_bool(node, "mask", TRUE);
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

	g_return_if_fail(rec != NULL);

	node = iconfig_node_traverse("hilights", FALSE);
	if (node != NULL) iconfig_node_list_remove(node, g_slist_index(hilights, rec));
}

static void hilight_destroy(HILIGHT_REC *rec)
{
	g_return_if_fail(rec != NULL);

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
	g_return_if_fail(rec != NULL);

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

static void sig_print_text(WINDOW_REC *window, SERVER_REC *server, const char *channel, gpointer level, const char *str)
{
	if (hilight_next) {
		hilight_next = FALSE;
		signal_stop();
	}
}

/* color name -> mirc color number */
static int mirc_color_name(const char *name)
{
	static const char *names[] = {
		"bla dbla", /* black */
		"blu dblu", /* blue */
		"gree dgree", /* green */
		"r dr br lr", /* red .. um.. only one of them. */
		"br dbr dy", /* brown / dark yello */
		"m p dm dp", /* magenta / purple */
		"o", /* orange */
		"y by", /* yellow */
		"bg lg", /* bright green */
		"c dc", /* cyan */
		"bc lc", /* bright cyan */
		"bb lb", /* bright blue */
		"bm bp lm lp", /* bright magenta/purple */
		"dgray dgrey", /* dark grey */
		"grey gray", /* grey */
		"w", /* white */
		NULL
	};

	const char *p, *pname;
	int n, ok;

	for (n = 0; names[n] != NULL; n++) {
		pname = name; ok = TRUE;
		for (p = names[n]; ; p++) {
			if (*p == ' ' || *p == '\0') {
                                if (ok) return n+1;
				if (*p == '\0') break;

				ok = TRUE;
				pname = name;
			} else if (toupper((int) *p) == toupper((int) *pname))
				pname++;
			else
				ok = FALSE;
		}
	}

	return -1;
}

char *hilight_match(const char *channel, const char *nickmask, int level, const char *str)
{
	GSList *tmp;
	const char *color;
	char number[MAX_INT_STRLEN];
	int len, best_match, colornum;

	g_return_val_if_fail(str != NULL, NULL);

	color = NULL; best_match = 0;
	for (tmp = hilights; tmp != NULL; tmp = tmp->next) {
		HILIGHT_REC *rec = tmp->data;

		if ((level & (rec->level > 0 ? rec->level : DEFAULT_HILIGHT_LEVEL)) == 0)
                        continue;
		if (!rec->nick && nickmask != NULL)
                        continue;
		if (rec->channels != NULL && (channel == NULL || strarray_find(rec->channels, channel) == -1))
			continue;
		if (rec->nickmask) {
			if (nickmask == NULL || !match_wildcards(rec->text, nickmask))
				continue;
		} else if (rec->regexp) {
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

	if (best_match == 0)
		return NULL;

	if (color == NULL) color = settings_get_str("hilight_color");
	if (isalpha((int) *color)) {
		/* color was specified with it's name - try to convert it */
		colornum = mirc_color_name(color);
		if (colornum <= 0) colornum = 16;

		ltoa(number, colornum);
		color = number;
	}
	return g_strconcat(isdigit(*color) ? "\003" : "", color, NULL);
}

static void sig_print_text_stripped(WINDOW_REC *window, SERVER_REC *server, const char *channel, gpointer plevel, const char *str)
{
	char *newstr, *color;
	int level, oldlevel;

	g_return_if_fail(str != NULL);

	level = GPOINTER_TO_INT(plevel);
	if (level & (MSGLEVEL_NOHILIGHT|MSGLEVEL_HILIGHT)) return;

	color = hilight_match(channel, NULL, level, str);
	if (color == NULL) return;

	if (*color == 3) {
		/* colorify */
                window->last_color = atoi(color+1);
	}

	if (window != active_win) {
		oldlevel = window->new_data;
		window->new_data = NEWDATA_HILIGHT;
		signal_emit("window hilight", 2, window, GINT_TO_POINTER(oldlevel));
		signal_emit("window activity", 2, window, GINT_TO_POINTER(oldlevel));
	}

	hilight_next = FALSE;

	signal_emit("print text stripped", 5, window, server, channel, GINT_TO_POINTER(level | MSGLEVEL_HILIGHT), str);
	signal_stop();

	newstr = g_strconcat(color, str, NULL);
	signal_emit("print text", 5, window, server, channel, GINT_TO_POINTER(level | MSGLEVEL_HILIGHT), newstr);
	g_free(newstr);

	hilight_next = TRUE;

	g_free_not_null(color);
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
		rec->nick = config_node_get_bool(node, "nick", TRUE);
		rec->nickmask = config_node_get_bool(node, "mask", FALSE);
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

/* SYNTAX: HILIGHT [-nick | -nonick] [-mask | -regexp | -word]
                   [-color <color>] [-level <level>]
		   [-channels <channels>] <text> */
static void cmd_hilight(const char *data)
{
        GHashTable *optlist;
	HILIGHT_REC *rec;
	char *colorarg, *levelarg, *chanarg, *text;
	char **channels;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (*data == '\0') {
		cmd_hilight_show();
		return;
	}

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			    PARAM_FLAG_GETREST, "hilight", &optlist, &text))
		return;

	chanarg = g_hash_table_lookup(optlist, "channels");
	levelarg = g_hash_table_lookup(optlist, "level");
	colorarg = g_hash_table_lookup(optlist, "color");

	if (*text == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	channels = (chanarg == NULL || *chanarg == '\0') ? NULL :
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

	rec->level = (levelarg == NULL || *levelarg == '\0') ? 0 :
		level2bits(replace_chars(levelarg, ',', ' '));
	rec->nick = settings_get_bool("hilight_only_nick") &&
		(rec->level == 0 || (rec->level & DEFAULT_HILIGHT_LEVEL) == rec->level) ?
		g_hash_table_lookup(optlist, "nonick") == NULL :
		g_hash_table_lookup(optlist, "nick") != NULL;
	rec->nickmask = g_hash_table_lookup(optlist, "mask") != NULL;
	rec->fullword = g_hash_table_lookup(optlist, "word") != NULL;
	rec->regexp = g_hash_table_lookup(optlist, "regexp") != NULL;

	if (colorarg != NULL && *colorarg != '\0')
		rec->color = g_strdup(colorarg);

	hilights = g_slist_append(hilights, rec);
	hilight_add_config(rec);

	hilight_print(g_slist_index(hilights, rec)+1, rec);
        cmd_params_free(free_arg);
}

/* SYNTAX: DEHILIGHT <id>|<mask> */
static void cmd_dehilight(const char *data)
{
	HILIGHT_REC *rec;
	GSList *tmp;

	if (is_numeric(data, ' ')) {
		/* with index number */
		tmp = g_slist_nth(hilights, atoi(data)-1);
		rec = tmp == NULL ? NULL : tmp->data;
	} else {
		/* with mask */
		char *chans[2] = { "*", NULL };
                rec = hilight_find(data, chans);
	}

	if (rec == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_HILIGHT_NOT_FOUND, data);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, IRCTXT_HILIGHT_REMOVED, rec->text);
		hilight_remove(rec);
	}
}

void hilight_text_init(void)
{
	hilight_next = FALSE;

	read_hilight_config();
	settings_add_str("misc", "hilight_color", "8");
	settings_add_bool("misc", "hilight_only_nick", TRUE);

	signal_add_first("print text", (SIGNAL_FUNC) sig_print_text);
	signal_add_first("print text stripped", (SIGNAL_FUNC) sig_print_text_stripped);
        signal_add("setup reread", (SIGNAL_FUNC) read_hilight_config);
	command_bind("hilight", NULL, (SIGNAL_FUNC) cmd_hilight);
	command_bind("dehilight", NULL, (SIGNAL_FUNC) cmd_dehilight);

	command_set_options("hilight", "-color -level -channels nick nonick mask word regexp");
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
