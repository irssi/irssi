/*
 statusbar-items.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

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
#include "signals.h"
#include "servers.h"
#include "misc.h"
#include "settings.h"
#include "special-vars.h"

#include "irc.h"
#include "channels.h"
#include "queries.h"
#include "irc-servers.h"
#include "nicklist.h"

#include "fe-windows.h"
#include "window-items.h"
#include "printtext.h"
#include "formats.h"

#include "screen.h"
#include "statusbar.h"
#include "gui-windows.h"
#include "gui-printtext.h"

/* how often to redraw lagging time (seconds) */
#define LAG_REFRESH_TIME 10

/* how often to check for new mail (seconds) */
#define MAIL_REFRESH_TIME 60

/* If we haven't been able to check lag for this long, "(??)" is added after
   the lag */
#define MAX_LAG_UNKNOWN_TIME 30

static int sbar_color_dim, sbar_color_normal, sbar_color_bold;
static int sbar_color_background, sbar_color_away, sbar_color_act_highlight;

static STATUSBAR_REC *mainbar;
static MAIN_WINDOW_REC *mainbar_window;
static int use_colors;

/* clock */
static SBAR_ITEM_REC *clock_item;
static int clock_timetag;
static time_t clock_last;

/* nick */
static SBAR_ITEM_REC *nick_item;

/* channel */
static SBAR_ITEM_REC *channel_item;

/* activity */
static SBAR_ITEM_REC *activity_item;
static GList *activity_list;

/* more */
static SBAR_ITEM_REC *more_item;

/* lag */
static SBAR_ITEM_REC *lag_item;
static int lag_timetag, lag_min_show;
static time_t lag_last_draw;

/* mbox counter */
static SBAR_ITEM_REC *mail_item;
static int mail_timetag, mail_last_count;
static time_t mail_last_mtime = -1;
static off_t mail_last_size = -1;

/* topic */
static SBAR_ITEM_REC *topic_item;
static STATUSBAR_REC *topic_bar;

static void item_default(SBAR_ITEM_REC *item, int get_size_only,
			 const char *str)
{
	SERVER_REC *server;
        WI_ITEM_REC *wiitem;
	char *parsed, *printstr;
	int len;

	if (active_win == NULL) {
		server = NULL;
                wiitem = NULL;
	} else {
		server = active_win->active_server;
                wiitem = active_win->active;
	}

	parsed = parse_special_string(str, server, wiitem, "", NULL,
				      PARSE_FLAG_ESCAPE_VARS);

	if (get_size_only) {
		item->min_size = item->max_size = format_get_length(parsed);
	} else {
		if (item->size < item->min_size) {
                        /* they're forcing us smaller than minimum size.. */
			len = format_real_length(parsed, item->size);
                        parsed[len] = '\0';
		}

                printstr = g_strconcat("%4", parsed, NULL);
		gui_printtext(item->xpos, item->bar->ypos, printstr);
                g_free(printstr);
	}
	g_free(parsed);
}

/* redraw clock */
static void statusbar_clock(SBAR_ITEM_REC *item, int get_size_only)
{
        item_default(item, get_size_only, "%c[%w$Z%c]");
}

/* check if we need to redraw clock.. */
static int statusbar_clock_timeout(void)
{
	struct tm *tm;
	time_t t;
	int min;

	tm = localtime(&clock_last);
	min = tm->tm_min;

	t = time(NULL);
	tm = localtime(&t);

	if (tm->tm_min != min) {
		/* minute changed, redraw! */
		statusbar_item_redraw(clock_item);
	}
	return 1;
}

/* redraw nick */
static void statusbar_nick(SBAR_ITEM_REC *item, int get_size_only)
{
        IRC_SERVER_REC *server;
	char *str, *usermode, *away;

	server = IRC_SERVER(active_win->active_server);
	usermode = server == NULL || server->usermode == NULL ||
		*server->usermode == '\0' ? "" :
		g_strdup_printf("(%%c+%%w%s)", server->usermode);
	away = server == NULL || !server->usermode_away ? "" :
                "(%GzZzZ%w)";

        str = g_strconcat("%c[%w$P$N", usermode, away, "%c]", NULL);
        item_default(item, get_size_only, str);
	g_free(str);
	if (*usermode != '\0') g_free(usermode);
}

static void sig_statusbar_nick_redraw(void)
{
	statusbar_item_redraw(nick_item);
}

/* redraw channel */
static void statusbar_channel(SBAR_ITEM_REC *item, int get_size_only)
{
        SERVER_REC *server;
        CHANNEL_REC *channel;
	char *str, *tmp;

	if (active_win->active != NULL) {
		/* channel/query */
                channel = CHANNEL(active_win->active);
		tmp = channel == NULL || channel->mode == NULL ||
			*channel->mode == '\0' ? "" :
			g_strdup_printf("(%%c+%%w%s)", channel->mode);
		str = g_strconcat("%c[%w$winref:$[.15]T", tmp, "%c]", NULL);
	} else {
		/* empty window */
                server = active_win->active_server;
		tmp = server == NULL ? "" :
			g_strdup_printf(":%s (change with ^X)", server->tag);
		str = g_strconcat("%c[%w$winref", tmp, "%c]", NULL);
	}

        item_default(item, get_size_only, str);

	g_free(str);
        if (*tmp != '\0') g_free(tmp);
}

static void sig_statusbar_channel_redraw(void)
{
	statusbar_item_redraw(channel_item);
}

static void sig_statusbar_channel_redraw_window(WINDOW_REC *window)
{
	if (is_window_visible(window))
		statusbar_item_redraw(channel_item);
}

static void sig_statusbar_channel_redraw_window_item(WI_ITEM_REC *item)
{
	WINDOW_REC *window;

        window = window_item_window(item);
	if (window->active == item && is_window_visible(window))
		statusbar_item_redraw(channel_item);
}

static char *get_activity_list(int normal, int hilight)
{
	GString *str;
	GList *tmp;
        char *ret;
        int is_det;

	str = g_string_new(NULL);

	for (tmp = activity_list; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *window = tmp->data;

		is_det = window->data_level >= DATA_LEVEL_HILIGHT;
		if ((!is_det && !normal) || (is_det && !hilight))
                        continue;

                if (str->len > 0)
			g_string_append(str, "%c,");

		switch (window->data_level) {
		case DATA_LEVEL_NONE:
		case DATA_LEVEL_TEXT:
			break;
		case DATA_LEVEL_MSG:
                        g_string_append(str, "%W");
			break;
		default:
			/*FIXME:if (window->hilight_color > 0) {
				int bg;

				bg = window->hilight_bg_color == -1 ?
					sbar_color_background :
					(window->hilight_bg_color << 4);
				set_color(stdscr, bg | mirc_colors[window->hilight_color%16]);
				g_string_append(str, "%M");
			} else */{
				g_string_append(str, "%M");
			}
			break;
		}
                g_string_sprintfa(str, "%d", window->refnum);
	}

	ret = str->len == 0 ? NULL : str->str;
        g_string_free(str, ret == NULL);
        return ret;
}

/* redraw activity, FIXME: if we didn't get enough size, this gets buggy.
   At least "Det:" isn't printed properly. also we should rearrange the
   act list so that the highest priority items comes first. */
static void statusbar_activity(SBAR_ITEM_REC *item, int get_size_only)
{
	GString *str;
	char *actlist, *detlist;

	if (use_colors) {
		actlist = get_activity_list(TRUE, TRUE);
                detlist = NULL;
	} else {
                actlist = get_activity_list(TRUE, FALSE);
                detlist = get_activity_list(FALSE, TRUE);
	}

	if (actlist == NULL && detlist == NULL) {
		if (get_size_only)
			item->min_size = item->max_size = 0;
		return;
	}

	str = g_string_new("%c[%w");

	if (actlist != NULL) {
		g_string_append(str, "Act: ");
		g_string_append(str, actlist);
                g_free(actlist);
	}
	if (detlist != NULL) {
                if (actlist != NULL)
			g_string_append(str, " ");
		g_string_append(str, "Det: ");
		g_string_append(str, detlist);
                g_free(detlist);
	}

	g_string_append(str, "%c]");
        item_default(item, get_size_only, str->str);
        g_string_free(str, TRUE);
}

static void sig_statusbar_activity_hilight(WINDOW_REC *window, gpointer oldlevel)
{
	GList *tmp;
	int inspos;

	g_return_if_fail(window != NULL);

	if (settings_get_bool("actlist_moves")) {
		/* Move the window to the first in the activity list */
		if (g_list_find(activity_list, window) != NULL)
			activity_list = g_list_remove(activity_list, window);
		if (window->data_level != 0)
			activity_list = g_list_prepend(activity_list, window);
		statusbar_item_redraw(activity_item);
		return;
	}

	if (g_list_find(activity_list, window) != NULL) {
		/* already in activity list */
		if (window->data_level == 0) {
			/* remove from activity list */
			activity_list = g_list_remove(activity_list, window);
			statusbar_item_redraw(activity_item);
		} else if (window->data_level != GPOINTER_TO_INT(oldlevel) ||
			 window->hilight_color != 0) {
			/* different level as last time (or maybe different
			   hilight color?), just redraw it. */
			statusbar_item_redraw(activity_item);
		}
		return;
	}

	if (window->data_level == 0)
		return;

	/* add window to activity list .. */
	inspos = 0;
	for (tmp = activity_list; tmp != NULL; tmp = tmp->next, inspos++) {
		WINDOW_REC *rec = tmp->data;

		if (window->refnum < rec->refnum) {
			activity_list =
				g_list_insert(activity_list, window, inspos);
			break;
		}
	}
	if (tmp == NULL)
		activity_list = g_list_append(activity_list, window);

	statusbar_item_redraw(activity_item);
}

static void sig_statusbar_activity_window_destroyed(WINDOW_REC *window)
{
	g_return_if_fail(window != NULL);

	if (g_list_find(activity_list, window) != NULL)
		activity_list = g_list_remove(activity_list, window);
	statusbar_item_redraw(activity_item);
}

static void sig_statusbar_activity_updated(void)
{
	statusbar_item_redraw(activity_item);
}

/* redraw -- more -- */
static void statusbar_more(SBAR_ITEM_REC *item, int get_size_only)
{
        item_default(item, get_size_only, "%_-- more --%_");
}

static void sig_statusbar_more_check_remove(WINDOW_REC *window)
{
	g_return_if_fail(window != NULL);

	if (!is_window_visible(window))
		return;

	if (more_item != NULL && WINDOW_GUI(window)->bottom) {
		statusbar_item_remove(more_item);
		more_item = NULL;
	}
}

static void sig_statusbar_more_check(WINDOW_REC *window)
{
	if (window == NULL || !is_window_visible(window))
		return;

	if (!WINDOW_GUI(window)->bottom) {
		if (more_item == NULL) {
			more_item = statusbar_item_create(mainbar, SBAR_PRIORITY_LOW, FALSE, statusbar_more);
			statusbar_redraw(mainbar);
		}
	} else if (more_item != NULL) {
		statusbar_item_remove(more_item);
		more_item = NULL;
	}
}

static void statusbar_lag(SBAR_ITEM_REC *item, int get_size_only)
{
	SERVER_REC *server;
	GString *str;
	int lag_unknown;
	time_t now;

	server = active_win == NULL ? NULL : active_win->active_server;
	if (server == NULL || server->lag_last_check == 0) {
                /* No lag information */
		if (get_size_only)
			item->min_size = item->max_size = 0;
		return;
	}

	now = time(NULL);
	str = g_string_new("%c[%wLag: %_");

	/* FIXME: ugly ugly.. */
	if (server->lag_sent == 0 || now-server->lag_sent < 5) {
		lag_unknown = now-server->lag_last_check >
			MAX_LAG_UNKNOWN_TIME+settings_get_int("lag_check_time");

		if (lag_min_show < 0 || (server->lag < lag_min_show && !lag_unknown)) {
                        /* small, lag, don't display */
			g_string_truncate(str, 0);
		} else {
			g_string_sprintfa(str, "%d.%02d", server->lag/1000,
					  (server->lag % 1000)/10);
			if (lag_unknown)
				g_string_append(str, " (??)");
		}
	} else {
		/* big lag, still waiting .. */
		g_string_sprintfa(str, "%ld (??)",
				  (long) (now-server->lag_sent));
	}

        if (str->len > 0)
		g_string_append(str, "%c]");

        item_default(item, get_size_only, str->str);

	g_string_free(str, TRUE);
}

static void sig_statusbar_lag_redraw(void)
{
	statusbar_item_redraw(lag_item);
}

static int statusbar_lag_timeout(void)
{
	/* refresh statusbar every 10 seconds */
	if (time(NULL)-lag_last_draw < LAG_REFRESH_TIME)
		return 1;

	statusbar_item_redraw(lag_item);
	return 1;
}

/* FIXME: this isn't very good.. it handles only mbox mailboxes.
   this whole mail feature should really be in it's own module with lots
   of other mail formats supported and people who don't want to use it
   wouldn't need to.. */
static int get_mail_count(void)
{
	struct stat statbuf;
	FILE *f;
	char str[512], *fname;
	int count;

	fname = g_getenv("MAIL");
	if (fname == NULL) return 0;

	if (stat(fname, &statbuf) != 0) {
		mail_last_mtime = -1;
		mail_last_size = -1;
                mail_last_count = 0;
		return 0;
	}

	if (statbuf.st_mtime == mail_last_mtime &&
	    statbuf.st_size == mail_last_size)
		return mail_last_count;
	mail_last_mtime = statbuf.st_mtime;
	mail_last_size = statbuf.st_size;

	f = fopen(fname, "r");
	if (f == NULL) {
                mail_last_count = 0;
		return 0;
	}

	count = 0;
	while (fgets(str, sizeof(str), f) != NULL) {
		if (strncmp(str, "From ", 5) == 0)
			count++;
		if (strncmp(str, "Subject: ", 9) == 0 &&
		    strstr(str, "FOLDER INTERNAL DATA")) {
			/* don't count these. */
			count--;
		}
	}

	fclose(f);
	mail_last_count = count;
	return count;
}

static void statusbar_mail(SBAR_ITEM_REC *item, int get_size_only)
{
	char countstr[MAX_INT_STRLEN], *str;
	int mail_count;

	mail_count = settings_get_bool("mail_counter") ? get_mail_count() : 0;

	if (mail_count <= 0) {
		if (get_size_only)
			item->min_size = item->max_size = 0;
		return;
	}

	ltoa(countstr, mail_count);
	str = g_strconcat("%c[%wMail: %_", countstr, "%_%c]", NULL);

	item_default(item, get_size_only, str);
        g_free(str);
}

static int statusbar_mail_timeout(void)
{
	statusbar_item_redraw(mail_item);
	return 1;
}

static void statusbar_topic(SBAR_ITEM_REC *item, int get_size_only)
{
        item_default(item, get_size_only, "$topic");
}

static void sig_statusbar_topic_redraw(void)
{
	if (topic_item != NULL) statusbar_item_redraw(topic_item);
}

static void sig_sidebars_redraw(void)
{
	GSList *tmp;

	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (rec->statusbar_channel_item != NULL)
                        statusbar_item_redraw(rec->statusbar_channel_item);
	}
}

static void topicbar_create(void)
{
	if (topic_bar != NULL)
		return;

	topic_bar = statusbar_create(STATUSBAR_POS_UP, 0);
	topic_item = statusbar_item_create(topic_bar, SBAR_PRIORITY_NORMAL, FALSE, statusbar_topic);
	topic_item->max_size = TRUE;
	statusbar_redraw(topic_bar);

	signal_add("window changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
	signal_add("window item changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
	signal_add("channel topic changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
	signal_add("query address changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
}

static void topicbar_destroy(void)
{
	if (topic_bar == NULL)
		return;

	statusbar_destroy(topic_bar);
	topic_item = NULL;
	topic_bar = NULL;

	signal_remove("window changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
	signal_remove("window item changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
	signal_remove("channel topic changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
	signal_remove("query address changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
}

static void mainbar_remove_items(void)
{
        statusbar_item_remove(clock_item);
        statusbar_item_remove(nick_item);
        statusbar_item_remove(channel_item);
	statusbar_item_remove(mail_item);
	statusbar_item_remove(lag_item);
        statusbar_item_remove(activity_item);
}

static void mainbar_add_items(MAIN_WINDOW_REC *window)
{
	mainbar = window->statusbar;
	mainbar_window = window;

	clock_item = statusbar_item_create(mainbar, SBAR_PRIORITY_HIGH, FALSE, statusbar_clock);
	nick_item = statusbar_item_create(mainbar, SBAR_PRIORITY_NORMAL, FALSE, statusbar_nick);
	channel_item = statusbar_item_create(mainbar, SBAR_PRIORITY_NORMAL, FALSE, statusbar_channel);
	mail_item = statusbar_item_create(mainbar, SBAR_PRIORITY_LOW, FALSE, statusbar_mail);
	lag_item = statusbar_item_create(mainbar, SBAR_PRIORITY_LOW, FALSE, statusbar_lag);
	activity_item = statusbar_item_create(mainbar, SBAR_PRIORITY_HIGH, FALSE, statusbar_activity);
}

static void sidebar_add_items(MAIN_WINDOW_REC *window)
{
	window->statusbar_channel_item =
		statusbar_item_create(window->statusbar, SBAR_PRIORITY_NORMAL, FALSE, statusbar_channel);
}

static void sidebar_remove_items(MAIN_WINDOW_REC *window)
{
	if (window->statusbar_channel_item != NULL) {
		statusbar_item_remove(window->statusbar_channel_item);
		window->statusbar_channel_item = NULL;
	}
}

static void sig_mainwindow_created(MAIN_WINDOW_REC *window)
{
	window->statusbar = statusbar_create(STATUSBAR_POS_MIDDLE, window->first_line+window->lines);
	sidebar_add_items(window);
}

static void sig_mainwindow_destroyed(MAIN_WINDOW_REC *window)
{
	if (window == mainbar_window) {
		mainbar = NULL;
		mainbar_window = NULL;
	}

	if (window->statusbar != NULL)
		statusbar_destroy(window->statusbar);
}

static void sig_main_statusbar_changed(WINDOW_REC *window)
{
	MAIN_WINDOW_REC *parent;

	if (window == NULL)
		return;

	parent = WINDOW_GUI(window)->parent;
	if (mainbar == parent->statusbar)
		return;

	if (mainbar != NULL) {
		mainbar_remove_items();
		sidebar_add_items(mainbar_window);
	}
	sidebar_remove_items(parent);
        mainbar_add_items(parent);
}

static void read_settings(void)
{
	use_colors = settings_get_bool("colors");
	if (settings_get_bool("topicbar"))
		topicbar_create();
	else if (!settings_get_bool("topicbar"))
		topicbar_destroy();

	lag_min_show = settings_get_int("lag_min_show")*10;

	sbar_color_background = settings_get_int("statusbar_background") << 4;
	sbar_color_dim = sbar_color_background |
		settings_get_int("statusbar_dim");
	sbar_color_normal = sbar_color_background |
		settings_get_int("statusbar_normal");
	sbar_color_bold = sbar_color_background |
		settings_get_int("statusbar_bold");
	sbar_color_away = sbar_color_background |
		settings_get_int("statusbar_away");
	sbar_color_act_highlight = sbar_color_background |
		settings_get_int("statusbar_act_highlight");
	statusbar_redraw(NULL);
}

void statusbar_items_init(void)
{
	GSList *tmp;

	settings_add_int("misc", "lag_min_show", 100);
	settings_add_bool("lookandfeel", "topicbar", TRUE);
	settings_add_bool("lookandfeel", "actlist_moves", FALSE);
	settings_add_bool("misc", "mail_counter", TRUE);

	settings_add_int("colors", "statusbar_background", 1);
	settings_add_int("colors", "statusbar_dim", 3);
	settings_add_int("colors", "statusbar_normal", 7);
	settings_add_int("colors", "statusbar_bold", 15);
	settings_add_int("colors", "statusbar_away", 10);
	settings_add_int("colors", "statusbar_act_highlight", 13);

	/* clock */
	clock_timetag = g_timeout_add(1000, (GSourceFunc) statusbar_clock_timeout, NULL);

	/* nick */
	signal_add("server connected", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_add("channel wholist", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_add("window changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_add("window item changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_add("nick mode changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_add("user mode changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_add("server nick changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_add("window server changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_add("away mode changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);

	/* channel */
	signal_add("window changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw);
	signal_add("window item changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw_window);
	signal_add("channel mode changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw_window_item);
	signal_add("window server changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw_window);
	signal_add("window refnum changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw_window);

	/* activity */
	activity_list = NULL;
	signal_add("window activity", (SIGNAL_FUNC) sig_statusbar_activity_hilight);
	signal_add("window destroyed", (SIGNAL_FUNC) sig_statusbar_activity_window_destroyed);
	signal_add("window refnum changed", (SIGNAL_FUNC) sig_statusbar_activity_updated);

	/* more */
	more_item = NULL;
	signal_add("gui page scrolled", (SIGNAL_FUNC) sig_statusbar_more_check_remove);
	signal_add("window changed", (SIGNAL_FUNC) sig_statusbar_more_check);
	signal_add("gui print text", (SIGNAL_FUNC) sig_statusbar_more_check);

	/* lag */
	lag_timetag = g_timeout_add(1000*LAG_REFRESH_TIME, (GSourceFunc) statusbar_lag_timeout, NULL);
	signal_add("server lag", (SIGNAL_FUNC) sig_statusbar_lag_redraw);
	signal_add("window server changed", (SIGNAL_FUNC) sig_statusbar_lag_redraw);

	/* mail */
	mail_timetag = g_timeout_add(1000*MAIL_REFRESH_TIME, (GSourceFunc) statusbar_mail_timeout, NULL);

	/* topic */
	topic_item = NULL; topic_bar = NULL;
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);

	read_settings();
	statusbar_redraw(NULL);

	/* middle bars */
        signal_add("mainwindow created", (SIGNAL_FUNC) sig_mainwindow_created);
        signal_add("mainwindow destroyed", (SIGNAL_FUNC) sig_mainwindow_destroyed);
	signal_add("window changed", (SIGNAL_FUNC) sig_main_statusbar_changed);
	signal_add("window refnum changed", (SIGNAL_FUNC) sig_sidebars_redraw);

	/* add statusbars to existing windows */
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next)
		sig_mainwindow_created(tmp->data);
	sig_main_statusbar_changed(active_win);
}

void statusbar_items_deinit(void)
{
	/* clock */
	g_source_remove(clock_timetag);

	/* nick */
	signal_remove("server connected", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_remove("channel wholist", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_remove("window changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_remove("window item changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_remove("nick mode changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_remove("user mode changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_remove("server nick changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_remove("window server changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);
	signal_remove("away mode changed", (SIGNAL_FUNC) sig_statusbar_nick_redraw);

	/* channel */
	signal_remove("window changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw);
	signal_remove("window item changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw_window);
	signal_remove("channel mode changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw_window_item);
	signal_remove("window server changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw_window);
	signal_remove("window refnum changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw_window);

	/* activity */
	signal_remove("window activity", (SIGNAL_FUNC) sig_statusbar_activity_hilight);
	signal_remove("window destroyed", (SIGNAL_FUNC) sig_statusbar_activity_window_destroyed);
	signal_remove("window refnum changed", (SIGNAL_FUNC) sig_statusbar_activity_updated);
	g_list_free(activity_list);

	/* more */
	signal_remove("gui page scrolled", (SIGNAL_FUNC) sig_statusbar_more_check_remove);
	signal_remove("window changed", (SIGNAL_FUNC) sig_statusbar_more_check);
	signal_remove("gui print text", (SIGNAL_FUNC) sig_statusbar_more_check);

	/* lag */
	g_source_remove(lag_timetag);
	signal_remove("server lag", (SIGNAL_FUNC) sig_statusbar_lag_redraw);
	signal_remove("window server changed", (SIGNAL_FUNC) sig_statusbar_lag_redraw);

	/* mail */
	g_source_remove(mail_timetag);

	/* topic */
	topicbar_destroy();
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	/* middle bars */
        signal_remove("mainwindow created", (SIGNAL_FUNC) sig_mainwindow_created);
        signal_remove("mainwindow destroyed", (SIGNAL_FUNC) sig_mainwindow_destroyed);
	signal_remove("window changed", (SIGNAL_FUNC) sig_main_statusbar_changed);
	signal_remove("window refnum changed", (SIGNAL_FUNC) sig_sidebars_redraw);
}
