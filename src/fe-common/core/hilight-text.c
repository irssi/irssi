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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "servers.h"
#include "channels.h"
#include "nicklist.h"

#include "hilight-text.h"
#include "nickmatch-cache.h"
#include "printtext.h"
#include "formats.h"

static NICKMATCH_REC *nickmatch;
static int never_hilight_level, default_hilight_level;
GSList *hilights;

static void reset_level_cache(void)
{
	GSList *tmp;

        never_hilight_level = MSGLEVEL_ALL & ~default_hilight_level;
	for (tmp = hilights; tmp != NULL; tmp = tmp->next) {
		HILIGHT_REC *rec = tmp->data;

		if (never_hilight_level & rec->level)
                        never_hilight_level &= ~rec->level;
	}
}

static void reset_cache(void)
{
	reset_level_cache();
	nickmatch_rebuild(nickmatch);
}

static void hilight_add_config(HILIGHT_REC *rec)
{
	CONFIG_NODE *node;

	g_return_if_fail(rec != NULL);

	node = iconfig_node_traverse("(hilights", TRUE);
	node = config_node_section(node, NULL, NODE_TYPE_BLOCK);

        iconfig_node_set_str(node, "text", rec->text);
        if (rec->level > 0) iconfig_node_set_int(node, "level", rec->level);
        if (rec->color) iconfig_node_set_str(node, "color", rec->color);
        if (rec->act_color) iconfig_node_set_str(node, "act_color", rec->act_color);
        if (rec->priority > 0) iconfig_node_set_int(node, "priority", rec->priority);
        iconfig_node_set_bool(node, "nick", rec->nick);
        iconfig_node_set_bool(node, "word", rec->word);
        if (rec->nickmask) iconfig_node_set_bool(node, "mask", TRUE);
        if (rec->fullword) iconfig_node_set_bool(node, "fullword", TRUE);
        if (rec->regexp) iconfig_node_set_bool(node, "regexp", TRUE);

	if (rec->channels != NULL && *rec->channels != NULL) {
		node = config_node_section(node, "channels", NODE_TYPE_LIST);
		iconfig_node_add_list(node, rec->channels);
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

#ifdef HAVE_REGEX_H
	if (rec->regexp_compiled) regfree(&rec->preg);
#endif
	if (rec->channels != NULL) g_strfreev(rec->channels);
	g_free_not_null(rec->color);
	g_free_not_null(rec->act_color);
	g_free(rec->text);
	g_free(rec);
}

static void hilights_destroy_all(void)
{
	g_slist_foreach(hilights, (GFunc) hilight_destroy, NULL);
	g_slist_free(hilights);
	hilights = NULL;
}

static void hilight_init_rec(HILIGHT_REC *rec)
{
#ifdef HAVE_REGEX_H
	if (rec->regexp_compiled) regfree(&rec->preg);
	rec->regexp_compiled = !rec->regexp ? FALSE :
		regcomp(&rec->preg, rec->text, REG_EXTENDED|REG_ICASE) == 0;
#endif
}

void hilight_create(HILIGHT_REC *rec)
{
	if (g_slist_find(hilights, rec) != NULL) {
		hilight_remove_config(rec);
		hilights = g_slist_remove(hilights, rec);
	}

	hilights = g_slist_append(hilights, rec);
	hilight_add_config(rec);

	hilight_init_rec(rec);

	signal_emit("hilight created", 1, rec);
}

void hilight_remove(HILIGHT_REC *rec)
{
	g_return_if_fail(rec != NULL);

	hilight_remove_config(rec);
	hilights = g_slist_remove(hilights, rec);

	signal_emit("hilight destroyed", 1, rec);
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

static int hilight_match_text(HILIGHT_REC *rec, const char *text,
			      int *match_beg, int *match_end)
{
	char *match;

	if (rec->regexp) {
#ifdef HAVE_REGEX_H
		regmatch_t rmatch[1];

		if (rec->regexp_compiled &&
		    regexec(&rec->preg, text, 1, rmatch, 0) == 0) {
			if (rmatch[0].rm_so > 0 &&
			    match_beg != NULL && match_end != NULL) {
				*match_beg = rmatch[0].rm_so;
				*match_end = rmatch[0].rm_eo;
			}
			return TRUE;
		}
#endif
	} else {
		match = rec->fullword ?
			stristr_full(text, rec->text) :
			stristr(text, rec->text);
		if (match != NULL) {
			if (match_beg != NULL && match_end != NULL) {
				*match_beg = (int) (match-text);
				*match_end = *match_beg + strlen(rec->text);
			}
			return TRUE;
		}
	}

        return FALSE;
}

#define hilight_match_level(rec, level) \
	(level & (((rec)->level != 0 ? rec->level : default_hilight_level)))

#define hilight_match_channel(rec, channel) \
	((rec)->channels == NULL || ((channel) != NULL && \
		strarray_find((rec)->channels, (channel)) != -1))

HILIGHT_REC *hilight_match(SERVER_REC *server, const char *channel,
			   const char *nick, const char *address,
			   int level, const char *str,
                           int *match_beg, int *match_end)
{
	GSList *tmp;
        CHANNEL_REC *chanrec;
	NICK_REC *nickrec;

	g_return_val_if_fail(str != NULL, NULL);

	if ((never_hilight_level & level) == level)
		return NULL;

	if (nick != NULL) {
                /* check nick mask hilights */
		chanrec = channel_find(server, channel);
		nickrec = chanrec == NULL ? NULL :
			nicklist_find(chanrec, nick);
		if (nickrec != NULL) {
                        HILIGHT_REC *rec;

			if (nickrec->host == NULL)
				nicklist_set_host(chanrec, nickrec, address);

			rec = nickmatch_find(nickmatch, nickrec);
			if (rec != NULL && hilight_match_level(rec, level))
				return rec;
		}
	}

	for (tmp = hilights; tmp != NULL; tmp = tmp->next) {
		HILIGHT_REC *rec = tmp->data;

		if (!rec->nickmask && hilight_match_level(rec, level) &&
		    hilight_match_channel(rec, channel) &&
		    hilight_match_text(rec, str, match_beg, match_end))
			return rec;
	}

        return NULL;
}

static char *hilight_get_act_color(HILIGHT_REC *rec)
{
	g_return_val_if_fail(rec != NULL, NULL);

	return g_strdup(rec->act_color != NULL ? rec->act_color :
			rec->color != NULL ? rec->color :
			settings_get_str("hilight_act_color"));
}

char *hilight_get_color(HILIGHT_REC *rec)
{
	const char *color;

	g_return_val_if_fail(rec != NULL, NULL);

	color = rec->color != NULL ? rec->color :
		settings_get_str("hilight_color");

	return format_string_expand(color, NULL);
}

void hilight_update_text_dest(TEXT_DEST_REC *dest, HILIGHT_REC *rec)
{
	dest->level |= MSGLEVEL_HILIGHT;

	if (rec->priority > 0)
		dest->hilight_priority = rec->priority;

	g_free_and_null(dest->hilight_color);
	if (rec->act_color != NULL && strcmp(rec->act_color, "%n") == 0)
		dest->level |= MSGLEVEL_NO_ACT;
        else
		dest->hilight_color = hilight_get_act_color(rec);
}

static void hilight_print(int index, HILIGHT_REC *rec);

static void sig_print_text(TEXT_DEST_REC *dest, const char *text,
			   const char *stripped)
{
	HILIGHT_REC *hilight;
	char *color, *newstr;
	int old_level, hilight_start, hilight_end, hilight_len;
	int nick_match;

	if (dest->level & MSGLEVEL_NOHILIGHT)
		return;

        hilight_start = hilight_end = 0;
	hilight = hilight_match(dest->server, dest->target,
				NULL, NULL, dest->level, stripped,
				&hilight_start,
				&hilight_end);
	if (hilight == NULL)
		return;

	nick_match = hilight->nick && (dest->level & (MSGLEVEL_PUBLIC|MSGLEVEL_ACTIONS)) == MSGLEVEL_PUBLIC;

	old_level = dest->level;
	if (!nick_match || (dest->level & MSGLEVEL_HILIGHT)) {
		/* update the level / hilight info */
		hilight_update_text_dest(dest, hilight);
	}

	if (nick_match)
		return; /* fe-messages.c should have taken care of this */

	if (old_level & MSGLEVEL_HILIGHT) {
		/* nick is highlighted, just set priority */
		return;
	}

	color = hilight_get_color(hilight);
	hilight_len = hilight_end-hilight_start;

	if (!hilight->word) {
		/* hilight whole line */
		char *tmp = strip_codes(text);
		newstr = g_strconcat(color, tmp, NULL);
                g_free(tmp);
	} else {
		/* hilight part of the line */
                GString *tmp;
                char *middle;
		int pos, color_pos, color_len;

                tmp = g_string_new(NULL);

                /* start of the line */
		pos = strip_real_length(text, hilight_start, NULL, NULL);
		g_string_append(tmp, text);
                g_string_truncate(tmp, pos);

		/* color */
                g_string_append(tmp, color);

		/* middle of the line, stripped */
		middle = strip_codes(text+pos);
                pos = tmp->len;
		g_string_append(tmp, middle);
                g_string_truncate(tmp, pos+hilight_len);
                g_free(middle);

		/* end of the line */
		pos = strip_real_length(text, hilight_end,
					&color_pos, &color_len);
		if (color_pos > 0)
			g_string_append_len(tmp, text+color_pos, color_len);
                else {
                        /* no colors in line, change back to default */
			g_string_append_c(tmp, 4);
			g_string_append_c(tmp, FORMAT_STYLE_DEFAULTS);
		}
		g_string_append(tmp, text+pos);

                newstr = tmp->str;
                g_string_free(tmp, FALSE);
	}

	signal_emit("print text", 3, dest, newstr, stripped);

	g_free(color);
	g_free(newstr);

	signal_stop();
}

HILIGHT_REC *hilight_match_nick(SERVER_REC *server, const char *channel,
			 const char *nick, const char *address,
			 int level, const char *msg)
{
        HILIGHT_REC *rec;

	rec = hilight_match(server, channel, nick, address,
			    level, msg, NULL, NULL);
	return (rec == NULL || !rec->nick) ? NULL : rec;
}

static void read_hilight_config(void)
{
	CONFIG_NODE *node;
	HILIGHT_REC *rec;
	GSList *tmp;
	char *text, *color;

	hilights_destroy_all();

	node = iconfig_node_traverse("hilights", FALSE);
	if (node == NULL) {
                reset_cache();
		return;
	}

	tmp = config_node_first(node->value);
	for (; tmp != NULL; tmp = config_node_next(tmp)) {
		node = tmp->data;

		if (node->type != NODE_TYPE_BLOCK)
			continue;

		text = config_node_get_str(node, "text", NULL);
		if (text == NULL || *text == '\0')
			continue;

		rec = g_new0(HILIGHT_REC, 1);
		hilights = g_slist_append(hilights, rec);

		rec->text = g_strdup(text);

		color = config_node_get_str(node, "color", NULL);
		rec->color = color == NULL || *color == '\0' ? NULL :
			g_strdup(color);

		color = config_node_get_str(node, "act_color", NULL);
		rec->act_color = color == NULL || *color == '\0' ? NULL :
			g_strdup(color);

		rec->level = config_node_get_int(node, "level", 0);
		rec->priority = config_node_get_int(node, "priority", 0);
		rec->nick = config_node_get_bool(node, "nick", TRUE);
		rec->word = config_node_get_bool(node, "word", TRUE);

		rec->nickmask = config_node_get_bool(node, "mask", FALSE);
		rec->fullword = config_node_get_bool(node, "fullword", FALSE);
		rec->regexp = config_node_get_bool(node, "regexp", FALSE);

		hilight_init_rec(rec);

		node = config_node_section(node, "channels", -1);
		if (node != NULL) rec->channels = config_node_get_list(node);
	}

        reset_cache();
}

static void hilight_print(int index, HILIGHT_REC *rec)
{
	char *chans, *levelstr;
	GString *options;

	options = g_string_new(NULL);
	if (!rec->nick || !rec->word) {
		if (rec->nick) g_string_append(options, "-nick ");
		if (rec->word) g_string_append(options, "-word ");
	}

	if (rec->nickmask) g_string_append(options, "-mask ");
	if (rec->fullword) g_string_append(options, "-full ");
	if (rec->regexp) {
		g_string_append(options, "-regexp ");
#ifdef HAVE_REGEX_H
		if (!rec->regexp_compiled)
			g_string_append(options, "[INVALID!] ");
#endif
	}

	if (rec->priority != 0)
		g_string_append_printf(options, "-priority %d ", rec->priority);
	if (rec->color != NULL)
		g_string_append_printf(options, "-color %s ", rec->color);
	if (rec->act_color != NULL)
		g_string_append_printf(options, "-actcolor %s ", rec->act_color);

	chans = rec->channels == NULL ? NULL :
		g_strjoinv(",", rec->channels);
	levelstr = rec->level == 0 ? NULL :
		bits2level(rec->level);
	if (levelstr != NULL)
		levelstr = g_strconcat(levelstr, " ", NULL);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
		    TXT_HILIGHT_LINE, index, rec->text,
		    chans != NULL ? chans : "",
		    levelstr != NULL ? levelstr : "",
		    options->str);
	g_free_not_null(chans);
	g_free_not_null(levelstr);
	g_string_free(options, TRUE);
}

static void cmd_hilight_show(void)
{
	GSList *tmp;
	int index;

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_HILIGHT_HEADER);
	index = 1;
	for (tmp = hilights; tmp != NULL; tmp = tmp->next, index++) {
		HILIGHT_REC *rec = tmp->data;

		hilight_print(index, rec);
	}
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_HILIGHT_FOOTER);
}

/* SYNTAX: HILIGHT [-nick | -word | -line] [-mask | -full | -regexp]
                   [-color <color>] [-actcolor <color>] [-level <level>]
		   [-channels <channels>] <text> */
static void cmd_hilight(const char *data)
{
        GHashTable *optlist;
	HILIGHT_REC *rec;
	char *colorarg, *actcolorarg, *levelarg, *priorityarg, *chanarg, *text;
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
	priorityarg = g_hash_table_lookup(optlist, "priority");
	colorarg = g_hash_table_lookup(optlist, "color");
	actcolorarg = g_hash_table_lookup(optlist, "actcolor");

	if (*text == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	channels = (chanarg == NULL || *chanarg == '\0') ? NULL :
		g_strsplit(chanarg, ",", -1);

	rec = hilight_find(text, channels);
	if (rec == NULL) {
		rec = g_new0(HILIGHT_REC, 1);

		/* default to nick/word hilighting */
                rec->nick = TRUE;
		rec->word = TRUE;

		rec->text = g_strdup(text);
		rec->channels = channels;
	} else {
		g_strfreev(channels);
	}

	rec->level = (levelarg == NULL || *levelarg == '\0') ? 0 :
		level2bits(replace_chars(levelarg, ',', ' '), NULL);
	rec->priority = priorityarg == NULL ? 0 : atoi(priorityarg);

	if (g_hash_table_lookup(optlist, "line") != NULL) {
		rec->word = FALSE;
		rec->nick = FALSE;
	}

	if (g_hash_table_lookup(optlist, "word") != NULL) {
		rec->word = TRUE;
                rec->nick = FALSE;
	}

	if (g_hash_table_lookup(optlist, "nick") != NULL)
                rec->nick = TRUE;

	rec->nickmask = g_hash_table_lookup(optlist, "mask") != NULL;
	rec->fullword = g_hash_table_lookup(optlist, "full") != NULL;
	rec->regexp = g_hash_table_lookup(optlist, "regexp") != NULL;

	if (colorarg != NULL) {
		g_free_and_null(rec->color);
		if (*colorarg != '\0')
			rec->color = g_strdup(colorarg);
	}
	if (actcolorarg != NULL) {
		g_free_and_null(rec->act_color);
		if (*actcolorarg != '\0')
			rec->act_color = g_strdup(actcolorarg);
	}

	hilight_create(rec);

	hilight_print(g_slist_index(hilights, rec)+1, rec);
        cmd_params_free(free_arg);

	reset_cache();
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
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_HILIGHT_NOT_FOUND, data);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_HILIGHT_REMOVED, rec->text);
		hilight_remove(rec);
                reset_cache();
	}
}

static void hilight_nick_cache(GHashTable *list, CHANNEL_REC *channel,
			       NICK_REC *nick)
{
	GSList *tmp;
	HILIGHT_REC *match;
        char *nickmask;
	int len, best_match;

	if (nick->host == NULL)
                return; /* don't check until host is known */

	nickmask = g_strconcat(nick->nick, "!", nick->host, NULL);

	best_match = 0; match = NULL;
	for (tmp = hilights; tmp != NULL; tmp = tmp->next) {
		HILIGHT_REC *rec = tmp->data;

		if (rec->nickmask &&
		    hilight_match_channel(rec, channel->name) &&
		    match_wildcards(rec->text, nickmask)) {
			len = strlen(rec->text);
			if (best_match < len) {
				best_match = len;
				match = rec;
			}
		}
	}
	g_free_not_null(nickmask);

	if (match != NULL)
                g_hash_table_insert(list, nick, match);
}

static void read_settings(void)
{
	default_hilight_level = settings_get_level("hilight_level");
	reset_level_cache();
}

void hilight_text_init(void)
{
	settings_add_str("lookandfeel", "hilight_color", "%Y");
	settings_add_str("lookandfeel", "hilight_act_color", "%M");
	settings_add_level("lookandfeel", "hilight_level", "PUBLIC DCCMSGS");

        read_settings();

	nickmatch = nickmatch_init(hilight_nick_cache);
	read_hilight_config();

	signal_add_first("print text", (SIGNAL_FUNC) sig_print_text);
        signal_add("setup reread", (SIGNAL_FUNC) read_hilight_config);
        signal_add("setup changed", (SIGNAL_FUNC) read_settings);

	command_bind("hilight", NULL, (SIGNAL_FUNC) cmd_hilight);
	command_bind("dehilight", NULL, (SIGNAL_FUNC) cmd_dehilight);
	command_set_options("hilight", "-color -actcolor -level -priority -channels nick word line mask full regexp");
}

void hilight_text_deinit(void)
{
	hilights_destroy_all();
        nickmatch_deinit(nickmatch);

	signal_remove("print text", (SIGNAL_FUNC) sig_print_text);
        signal_remove("setup reread", (SIGNAL_FUNC) read_hilight_config);
        signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	command_unbind("hilight", (SIGNAL_FUNC) cmd_hilight);
	command_unbind("dehilight", (SIGNAL_FUNC) cmd_dehilight);
}
