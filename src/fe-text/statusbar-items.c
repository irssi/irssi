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
#include "misc.h"
#include "settings.h"
#include "special-vars.h"

#include "window-items.h"
#include "formats.h"

#include "statusbar.h"
#include "gui-printtext.h"

/* how often to redraw lagging time (seconds) */
#define LAG_REFRESH_TIME 10

/* how often to check for new mail (seconds) */
#define MAIL_REFRESH_TIME 60

/* If we haven't been able to check lag for this long, "(??)" is added after
   the lag */
#define MAX_LAG_UNKNOWN_TIME 30

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
static SBAR_ITEM_REC *window_item;

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
			 const char *str, const char *data)
{
	SERVER_REC *server;
	WI_ITEM_REC *wiitem;
        char *tmpstr, *tmpstr2;
	int len;

	if (active_win == NULL) {
		server = NULL;
                wiitem = NULL;
	} else {
		server = active_win->active_server;
                wiitem = active_win->active;
	}

	/* expand $variables */
	tmpstr = parse_special_string(str, server, wiitem, data, NULL,
				      PARSE_FLAG_ESCAPE_VARS);

	/* expand templates */
        str = tmpstr;
	tmpstr2 = theme_format_expand_data(current_theme, &str,
					   'n', '0' + item->bar->color,
					   NULL, NULL,
					   EXPAND_FLAG_ROOT |
					   EXPAND_FLAG_IGNORE_REPLACES |
					   EXPAND_FLAG_IGNORE_EMPTY);
	g_free(tmpstr);

	/* remove color codes */
	tmpstr = strip_codes(tmpstr2);
        g_free(tmpstr2);

	if (get_size_only) {
		item->min_size = item->max_size = format_get_length(tmpstr);
	} else {
		if (item->size < item->min_size) {
                        /* they're forcing us smaller than minimum size.. */
			len = format_real_length(tmpstr, item->size);
                        tmpstr[len] = '\0';
		}

		tmpstr2 = g_strconcat(item->bar->color_string, tmpstr, NULL);
		gui_printtext(item->xpos, item->bar->ypos, tmpstr2);
                g_free(tmpstr2);
	}
	g_free(tmpstr);
}

/* redraw clock */
static void statusbar_clock(SBAR_ITEM_REC *item, int get_size_only)
{
	item_default(item, get_size_only, "{sb $Z}", "");
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
                clock_last = t;
		statusbar_item_redraw(clock_item);
	}
	return 1;
}

/* redraw nick */
static void statusbar_nick(SBAR_ITEM_REC *item, int get_size_only)
{
	item_default(item, get_size_only,
		     "{sb $P$N{sbmode $usermode}{sbaway $A}}", "");
}

static void sig_statusbar_nick_redraw(void)
{
	statusbar_item_redraw(nick_item);
}

/* redraw window */
static void statusbar_window(SBAR_ITEM_REC *item, int get_size_only)
{
	if (active_win->active != NULL) {
		item_default(item, get_size_only,
			     "{sb $winref:$T{sbmode $M}}", "");
	} else {
		item_default(item, get_size_only,
			     "{sb $winref{sbservertag $tag}}", "");
	}
}

static void sig_statusbar_window_redraw(void)
{
	statusbar_item_redraw(window_item);
}

static void sig_statusbar_window_redraw_window(WINDOW_REC *window)
{
	if (is_window_visible(window))
		statusbar_item_redraw(window_item);
}

static void sig_statusbar_window_redraw_window_item(WI_ITEM_REC *item)
{
	WINDOW_REC *window;

        window = window_item_window(item);
	if (window->active == item && is_window_visible(window))
		statusbar_item_redraw(window_item);
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

		g_string_append(str, "%c");
                if (str->len > 2)
			g_string_append_c(str, ',');

		switch (window->data_level) {
		case DATA_LEVEL_NONE:
		case DATA_LEVEL_TEXT:
			break;
		case DATA_LEVEL_MSG:
                        g_string_append(str, "%W");
			break;
		default:
			g_string_append(str, window->hilight_color == NULL ?
					"%M" : window->hilight_color);
			break;
		}
		g_string_sprintfa(str, "%d", window->refnum);

                /* make sure the background is returned to default */
		g_string_append(str, "%n");
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
	char *actlist, *detlist, *data;

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

	data = g_strconcat("{sbact ", actlist != NULL ? actlist : "",
			   " ", detlist != NULL ? detlist : "", "}", NULL);
	item_default(item, get_size_only, data, "");
        g_free(data);

	g_free_not_null(actlist);
        g_free_not_null(detlist);
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
	item_default(item, get_size_only, "{sbmore}", "");
}

static void sig_statusbar_more_check_remove(WINDOW_REC *window)
{
	g_return_if_fail(window != NULL);

	if (!is_window_visible(window))
		return;

	if (more_item != NULL && WINDOW_GUI(window)->view->bottom) {
		statusbar_item_remove(more_item);
		more_item = NULL;
	}
}

static void sig_statusbar_more_check(WINDOW_REC *window)
{
	if (window == NULL || !is_window_visible(window))
		return;

	if (!WINDOW_GUI(window)->view->bottom) {
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
	str = g_string_new(NULL);

	/* FIXME: ugly ugly.. */
	if (server->lag_sent == 0 || now-server->lag_sent < 5) {
		lag_unknown = now-server->lag_last_check >
			MAX_LAG_UNKNOWN_TIME+settings_get_int("lag_check_time");

		if (lag_min_show < 0 || (server->lag < lag_min_show && !lag_unknown)) {
                        /* small lag, don't display */
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

	item_default(item, get_size_only, "{sblag $0-}", str->str);

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
	char countstr[MAX_INT_STRLEN];
	int mail_count;

	mail_count = settings_get_bool("mail_counter") ? get_mail_count() : 0;

	if (mail_count <= 0) {
		if (get_size_only)
			item->min_size = item->max_size = 0;
		return;
	}

	ltoa(countstr, mail_count);
	item_default(item, get_size_only, "{sbmail $0-}", countstr);
}

static int statusbar_mail_timeout(void)
{
	statusbar_item_redraw(mail_item);
	return 1;
}

static void statusbar_topic(SBAR_ITEM_REC *item, int get_size_only)
{
        item_default(item, get_size_only, "$topic", "");
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

		if (rec->statusbar_window_item != NULL)
                        statusbar_item_redraw(rec->statusbar_window_item);
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
        statusbar_item_remove(window_item);
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
	window_item = statusbar_item_create(mainbar, SBAR_PRIORITY_NORMAL, FALSE, statusbar_window);
	mail_item = statusbar_item_create(mainbar, SBAR_PRIORITY_LOW, FALSE, statusbar_mail);
	lag_item = statusbar_item_create(mainbar, SBAR_PRIORITY_LOW, FALSE, statusbar_lag);
	activity_item = statusbar_item_create(mainbar, SBAR_PRIORITY_HIGH, FALSE, statusbar_activity);
}

static void sidebar_add_items(MAIN_WINDOW_REC *window)
{
	window->statusbar_window_item =
		statusbar_item_create(window->statusbar, SBAR_PRIORITY_NORMAL, FALSE, statusbar_window);
}

static void sidebar_remove_items(MAIN_WINDOW_REC *window)
{
	if (window->statusbar_window_item != NULL) {
		statusbar_item_remove(window->statusbar_window_item);
		window->statusbar_window_item = NULL;
	}
}

static void sig_mainwindow_created(MAIN_WINDOW_REC *window)
{
	window->statusbar =
		statusbar_create(STATUSBAR_POS_MIDDLE,
				 window->first_line+window->height);
        ((STATUSBAR_REC *) window->statusbar)->window = window;
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
	use_colors = settings_get_bool("colors") && has_colors();
	if (settings_get_bool("topicbar"))
		topicbar_create();
	else
		topicbar_destroy();

	lag_min_show = settings_get_int("lag_min_show")*10;
	statusbar_redraw(NULL);
}

void statusbar_items_init(void)
{
	GSList *tmp;

	settings_add_int("misc", "lag_min_show", 100);
	settings_add_bool("lookandfeel", "topicbar", TRUE);
	settings_add_bool("lookandfeel", "actlist_moves", FALSE);
	settings_add_bool("misc", "mail_counter", TRUE);

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
	signal_add("window changed", (SIGNAL_FUNC) sig_statusbar_window_redraw);
	signal_add("window item changed", (SIGNAL_FUNC) sig_statusbar_window_redraw_window);
	signal_add("channel mode changed", (SIGNAL_FUNC) sig_statusbar_window_redraw_window_item);
	signal_add("window server changed", (SIGNAL_FUNC) sig_statusbar_window_redraw_window);
	signal_add("window refnum changed", (SIGNAL_FUNC) sig_statusbar_window_redraw_window);

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
	signal_remove("window changed", (SIGNAL_FUNC) sig_statusbar_window_redraw);
	signal_remove("window item changed", (SIGNAL_FUNC) sig_statusbar_window_redraw_window);
	signal_remove("channel mode changed", (SIGNAL_FUNC) sig_statusbar_window_redraw_window_item);
	signal_remove("window server changed", (SIGNAL_FUNC) sig_statusbar_window_redraw_window);
	signal_remove("window refnum changed", (SIGNAL_FUNC) sig_statusbar_window_redraw_window);

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
