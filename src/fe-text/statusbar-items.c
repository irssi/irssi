/*
 gui-statusbar-items.c : irssi

    Copyright (C) 1999 Timo Sirainen

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

/* redraw clock */
static void statusbar_clock(SBAR_ITEM_REC *item, int ypos)
{
	struct tm *tm;
	char str[6];

	clock_last = time(NULL);
	tm = localtime(&clock_last);

	g_snprintf(str, sizeof(str), "%02d:%02d", tm->tm_hour, tm->tm_min);

	move(ypos, item->xpos);
	set_color(stdscr, sbar_color_dim); addch('[');
	set_color(stdscr, sbar_color_bold); addstr(str);
	set_color(stdscr, sbar_color_dim); addch(']');

	screen_refresh(NULL);
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
static void statusbar_nick(SBAR_ITEM_REC *item, int ypos)
{
	CHANNEL_REC *channel;
	SERVER_REC *server;
	IRC_SERVER_REC *ircserver;
	NICK_REC *nickrec;
	int size_needed;
	int umode_size;
	char nick[10];

	server = active_win == NULL ? NULL : active_win->active_server;
	ircserver = IRC_SERVER(server);

	umode_size = ircserver == NULL || ircserver->usermode == NULL ||
		ircserver->usermode[0] == '\0' ? 0 :
		strlen(ircserver->usermode)+3;

	/* nick */
	if (server == NULL || server->nick == NULL) {
		nick[0] = '\0';
		nickrec = NULL;
	} else {
		strncpy(nick, server->nick, 9);
		nick[9] = '\0';

		channel = CHANNEL(active_win->active);
		nickrec = channel == NULL ? NULL :
			nicklist_find(channel, server->nick);
	}

	size_needed = 2 + strlen(nick) + umode_size +
		(server != NULL && server->usermode_away ? 7 : 0) +
		(nickrec != NULL && (nickrec->op || nickrec->voice) ? 1 : 0); /* @ + */

	if (item->size != size_needed) {
		/* we need more (or less..) space! */
		statusbar_item_resize(item, size_needed);
		return;
	}

	/* size ok, draw the nick */
	move(ypos, item->xpos);

	set_color(stdscr, sbar_color_dim); addch('[');
	if (nickrec != NULL && (nickrec->op || nickrec->voice)) {
		set_color(stdscr, sbar_color_bold);
		addch(nickrec->op ? '@' : '+');
	}
	set_color(stdscr, sbar_color_normal); addstr(nick);
	if (umode_size) {
		set_color(stdscr, sbar_color_bold); addch('(');
		set_color(stdscr, sbar_color_dim); addch('+');
		set_color(stdscr, sbar_color_normal); addstr(ircserver->usermode);
		set_color(stdscr, sbar_color_bold); addch(')');
	}
	if (server != NULL && server->usermode_away) {
		set_color(stdscr, sbar_color_normal); addstr(" (");
		set_color(stdscr, sbar_color_away); addstr("zZzZ");
		set_color(stdscr, sbar_color_normal); addch(')');
	}
	set_color(stdscr, sbar_color_dim); addch(']');
	screen_refresh(NULL);
}

static void sig_statusbar_nick_redraw(void)
{
	statusbar_item_redraw(nick_item);
}

static WINDOW_REC *mainwindow_find_sbar(SBAR_ITEM_REC *item)
{
	GSList *tmp;

	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *rec = tmp->data;

		if (rec->statusbar_channel_item == item)
			return rec->active;
	}

	return active_win;
}

/* redraw channel */
static void statusbar_channel(SBAR_ITEM_REC *item, int ypos)
{
    WINDOW_REC *window;
    WI_ITEM_REC *witem;
    CHANNEL_REC *channel;
    SERVER_REC *server;
    gchar channame[21], winnum[MAX_INT_STRLEN], *tmpname;
    int size_needed;
    int mode_size;

    window = item->bar->pos != STATUSBAR_POS_MIDDLE ? active_win :
            mainwindow_find_sbar(item);
    server = window == NULL ? NULL : window->active_server;

    ltoa(winnum, window == NULL ? 0 : window->refnum);

    witem = window != NULL && (IS_CHANNEL(window->active) || IS_QUERY(window->active)) ?
	    window->active : NULL;
    if (witem == NULL)
    {
	/* display server tag */
        channame[0] = '\0';
	mode_size = 0;
	channel = NULL;

	size_needed = 3 + strlen(winnum) + (server == NULL ? 0 : (17+strlen(server->tag)));
    }
    else
    {
	/* display channel + mode */
        tmpname = show_lowascii(witem->name);
        strncpy(channame, tmpname, 20); channame[20] = '\0';
        g_free(tmpname);

	channel = CHANNEL(witem);
	if (channel == NULL) {
                mode_size = 0;
	} else {
		mode_size = strlen(channel->mode);
		if (mode_size > 0) mode_size += 3; /* (+) */
	}

	size_needed = 3 + strlen(winnum) + strlen(channame) + mode_size;
    }

    if (item->size != size_needed)
    {
        /* we need more (or less..) space! */
        statusbar_item_resize(item, size_needed);
        return;
    }

    move(ypos, item->xpos);
    set_color(stdscr, sbar_color_dim); addch('[');

    /* window number */
    set_color(stdscr, sbar_color_normal); addstr(winnum);
    set_color(stdscr, sbar_color_dim); addch(':');

    if (channame[0] == '\0' && server != NULL)
    {
	/* server tag */
	set_color(stdscr, sbar_color_normal); addstr(server->tag);
        addstr(" (change with ^X)");
    }
    else if (channame[0] != '\0')
    {
	/* channel + mode */
	set_color(stdscr, sbar_color_normal); addstr(channame);
	if (mode_size)
	{
	    set_color(stdscr, sbar_color_bold); addch('(');
	    set_color(stdscr, sbar_color_dim); addch('+');
	    set_color(stdscr, sbar_color_normal); addstr(channel->mode);
	    set_color(stdscr, sbar_color_bold); addch(')');
	}
    }
    set_color(stdscr, sbar_color_dim); addch(']');
    screen_refresh(NULL);
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

static void draw_activity(gchar *title, gboolean act, gboolean det)
{
    WINDOW_REC *window;
    GList *tmp;
    gchar str[MAX_INT_STRLEN];
    gboolean first, is_det;

    set_color(stdscr, sbar_color_normal); addstr(title);

    first = TRUE;
    for (tmp = activity_list; tmp != NULL; tmp = tmp->next)
    {
	window = tmp->data;

	is_det = window->new_data >= NEWDATA_HILIGHT;
	if (is_det && !det) continue;
	if (!is_det && !act) continue;

	if (first)
	    first = FALSE;
	else
	{
	    set_color(stdscr, sbar_color_dim);
	    addch(',');
	}

	ltoa(str, window->refnum);
	switch (window->new_data)
	{
	case NEWDATA_TEXT:
		set_color(stdscr, sbar_color_dim);
		break;
	case NEWDATA_MSG:
		set_color(stdscr, sbar_color_bold);
		break;
	case NEWDATA_HILIGHT:
		if (window->last_color > 0)
			set_color(stdscr, sbar_color_background | mirc_colors[window->last_color]);
		else
			set_color(stdscr, sbar_color_act_highlight);
		break;
	}
	addstr(str);
    }
}

/* redraw activity */
static void statusbar_activity(SBAR_ITEM_REC *item, int ypos)
{
    WINDOW_REC *window;
    GList *tmp;
    gchar str[MAX_INT_STRLEN];
    int size_needed;
    gboolean act, det;

    size_needed = 0; act = det = FALSE;
    for (tmp = activity_list; tmp != NULL; tmp = tmp->next)
    {
	window = tmp->data;

	size_needed += 1+ltoa(str, window->refnum);

	if (!use_colors && window->new_data >= NEWDATA_HILIGHT)
	    det = TRUE;
	else
	    act = TRUE;
    }

    if (act) size_needed += 6; /* [Act: ], -1 */
    if (det) size_needed += 6; /* [Det: ], -1 */
    if (act && det) size_needed--;

    if (item->size != size_needed)
    {
        /* we need more (or less..) space! */
        statusbar_item_resize(item, size_needed);
        return;
    }

    if (item->size == 0)
        return;

    move(ypos, item->xpos);
    set_color(stdscr, sbar_color_dim); addch('[');
    if (act) draw_activity("Act: ", TRUE, !det);
    if (act && det) addch(' ');
    if (det) draw_activity("Det: ", FALSE, TRUE);
    set_color(stdscr, sbar_color_dim); addch(']');

    screen_refresh(NULL);
}

static void sig_statusbar_activity_hilight(WINDOW_REC *window, gpointer oldlevel)
{
    GList *tmp;
    int inspos;

    g_return_if_fail(window != NULL);

    if (settings_get_bool("actlist_moves"))
    {
	/* Move the window to the first in the activity list */
	if (g_list_find(activity_list, window) != NULL)
	    activity_list = g_list_remove(activity_list, window);
	if (window->new_data != 0)
	    activity_list = g_list_prepend(activity_list, window);
	statusbar_item_redraw(activity_item);
	return;
    }

    if (g_list_find(activity_list, window) != NULL)
    {
	/* already in activity list */
	if (window->new_data == 0)
	{
	    /* remove from activity list */
	    activity_list = g_list_remove(activity_list, window);
	    statusbar_item_redraw(activity_item);
	}
	else if (window->new_data != GPOINTER_TO_INT(oldlevel) ||
		 window->last_color != 0)
	{
		/* different level as last time (or maybe different
		   hilight color?), just redraw it. */
		statusbar_item_redraw(activity_item);
	}
        return;
    }

    if (window->new_data == 0)
	    return;

    /* add window to activity list .. */
    inspos = 0;
    for (tmp = activity_list; tmp != NULL; tmp = tmp->next, inspos++)
    {
        WINDOW_REC *rec = tmp->data;

	if (window->refnum < rec->refnum)
	{
	    activity_list = g_list_insert(activity_list, window, inspos);
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
static void statusbar_more(SBAR_ITEM_REC *item, int ypos)
{
	if (item->size != 10) return;

	move(ypos, item->xpos);
	set_color(stdscr, sbar_color_bold); addstr("-- more --");
	screen_refresh(NULL);
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
	g_return_if_fail(window != NULL);

	if (!is_window_visible(window))
		return;

	if (!WINDOW_GUI(window)->bottom) {
		if (more_item == NULL) {
			more_item = statusbar_item_create(mainbar, 10, FALSE, statusbar_more);
			statusbar_redraw(mainbar);
		}
	} else if (more_item != NULL) {
		statusbar_item_remove(more_item);
		more_item = NULL;
	}
}

static void statusbar_lag(SBAR_ITEM_REC *item, int ypos)
{
	SERVER_REC *server;
	GString *str;
	int size_needed, lag_unknown;
	time_t now;

	now = time(NULL);
	str = g_string_new(NULL);

	server = active_win == NULL ? NULL : active_win->active_server;
	if (server == NULL || server->lag_last_check == 0)
		size_needed = 0;
	else if (server->lag_sent == 0 || now-server->lag_sent < 5) {
		lag_unknown = now-server->lag_last_check >
			MAX_LAG_UNKNOWN_TIME+settings_get_int("lag_check_time");

		if (lag_min_show < 0 || (server->lag < lag_min_show && !lag_unknown))
			size_needed = 0; /* small lag, don't display */
		else {
			g_string_sprintf(str, "%d.%02d", server->lag/1000, (server->lag % 1000)/10);
			if (lag_unknown)
				g_string_append(str, " (??)");
			size_needed = str->len+7;
		}
	} else {
		/* big lag, still waiting .. */
		g_string_sprintf(str, "%ld (??)", (long) (now-server->lag_sent));
		size_needed = str->len+7;
	}

	if (item->size != size_needed) {
		/* we need more (or less..) space! */
		statusbar_item_resize(item, size_needed);
		g_string_free(str, TRUE);
		return;
	}

	if (item->size != 0) {
		lag_last_draw = now;
		move(ypos, item->xpos);
		set_color(stdscr, sbar_color_dim); addch('[');
		set_color(stdscr, sbar_color_normal); addstr("Lag: ");

		set_color(stdscr, sbar_color_bold); addstr(str->str);
		set_color(stdscr, sbar_color_dim); addch(']');

		screen_refresh(NULL);
	}
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

static void statusbar_mail(SBAR_ITEM_REC *item, int ypos)
{
	char str[MAX_INT_STRLEN];
	int size_needed, mail_count;

	mail_count = settings_get_bool("mail_counter") ? get_mail_count() : 0;

	ltoa(str, mail_count);
	if (*str == '\0' || mail_count <= 0)
		size_needed = 0;
	else
		size_needed = strlen(str) + 8;

	if (item->size != size_needed) {
		/* we need more (or less..) space! */
		statusbar_item_resize(item, size_needed);
		return;
	}

	if (size_needed == 0)
		return;

	move(ypos, item->xpos);
	set_color(stdscr, sbar_color_dim); addch('[');
	set_color(stdscr, sbar_color_normal); addstr("Mail: ");

	set_color(stdscr, sbar_color_bold); addstr(str);
	set_color(stdscr, sbar_color_dim); addch(']');

	screen_refresh(NULL);
}

static int statusbar_mail_timeout(void)
{
	statusbar_item_redraw(mail_item);
	return 1;
}

static void statusbar_topic(SBAR_ITEM_REC *item, int ypos)
{
	CHANNEL_REC *channel;
	QUERY_REC *query;
	char *str, *topic;

	if (item->size != COLS-2) {
		/* get all space for topic */
		statusbar_item_resize(item, COLS-2);
		return;
	}

	move(ypos, item->xpos);
	set_bg(stdscr, settings_get_int("statusbar_background") << 4);
	clrtoeol(); set_bg(stdscr, 0);

	if (active_win == NULL)
		return;

	topic = NULL;
	channel = CHANNEL(active_win->active);
	query = QUERY(active_win->active);
	if (channel != NULL && channel->topic != NULL) topic = channel->topic;
	if (query != NULL && query->address != NULL) topic = query->address;

	if (topic != NULL) {
		topic = strip_codes(topic);
		str = g_strdup_printf("%.*s", item->size, topic);
		set_color(stdscr, sbar_color_normal); addstr(str);
		g_free(str);
		g_free(topic);
	}

	screen_refresh(NULL);
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
	topic_item = statusbar_item_create(topic_bar, 0, FALSE, statusbar_topic);
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

	clock_item = statusbar_item_create(mainbar, 7, FALSE, statusbar_clock);
	nick_item = statusbar_item_create(mainbar, 2, FALSE, statusbar_nick);
	channel_item = statusbar_item_create(mainbar, 2, FALSE, statusbar_channel);
	mail_item = statusbar_item_create(mainbar, 0, FALSE, statusbar_mail);
	lag_item = statusbar_item_create(mainbar, 0, FALSE, statusbar_lag);
	activity_item = statusbar_item_create(mainbar, 0, FALSE, statusbar_activity);
}

static void sidebar_add_items(MAIN_WINDOW_REC *window)
{
	window->statusbar_channel_item =
		statusbar_item_create(window->statusbar, 3, FALSE, statusbar_channel);
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
