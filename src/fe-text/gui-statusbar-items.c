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
#include "server.h"
#include "misc.h"
#include "settings.h"

#include "irc.h"
#include "channels.h"
#include "query.h"
#include "irc-server.h"
#include "nicklist.h"

#include "windows.h"

#include "screen.h"
#include "gui-statusbar.h"
#include "gui-mainwindows.h"
#include "gui-windows.h"

/* how often to redraw lagging time */
#define LAG_REFRESH_TIME 10
/* If we haven't been able to check lag for this long, "(??)" is added after
   the lag */
#define MAX_LAG_UNKNOWN_TIME 30

/* clock */
static int clock_tag, clock_timetag;
static time_t clock_last;

/* nick */
static int nick_tag;

/* channel */
static int channel_tag;

/* activity */
static int activity_tag;
static GList *activity_list;

/* more */
static int more_tag;

/* lag */
static int lag_tag, lag_timetag, lag_min_show;
static time_t lag_last_draw;

/* topic */
static int topic_tag;

/* redraw clock */
static void statusbar_clock(int xpos, int ypos, int size)
{
    struct tm *tm;
    gchar str[5];

    clock_last = time(NULL);
    tm = localtime(&clock_last);

    sprintf(str, "%02d:%02d", tm->tm_hour, tm->tm_min);

    move(ypos, xpos);
    set_color((1 << 4)+3); addch('[');
    set_color((1 << 4)+15); addstr(str);
    set_color((1 << 4)+3); addch(']');

    screen_refresh();
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

    if (tm->tm_min != min)
    {
        /* minute changed, redraw! */
        gui_statusbar_redraw(clock_tag);
    }
    return 1;
}

/* redraw nick */
static void statusbar_nick(int xpos, int ypos, int size)
{
    CHANNEL_REC *channel;
    IRC_SERVER_REC *server;
    NICK_REC *nickrec;
    int size_needed;
    int umode_size;
    gchar nick[10];

    server = (IRC_SERVER_REC *) (active_win == NULL ? NULL : active_win->active_server);

    umode_size = server == NULL || server->usermode == NULL ? 0 : strlen(server->usermode)+3;

    /* nick */
    if (server == NULL || server->nick == NULL)
    {
        nick[0] = '\0';
        nickrec = NULL;
    }
    else
    {
        strncpy(nick, server->nick, 9);
	nick[9] = '\0';

        channel = irc_item_channel(active_win->active);
	nickrec = channel == NULL ? NULL : nicklist_find(channel, server->nick);
    }

    size_needed = 2 + strlen(nick) + umode_size +
        (server != NULL && server->usermode_away ? 7 : 0) +
        (nickrec != NULL && (nickrec->op || nickrec->voice) ? 1 : 0); /* @ + */

    if (size != size_needed)
    {
        /* we need more (or less..) space! */
        gui_statusbar_resize(nick_tag, size_needed);
        return;
    }

    /* size ok, draw the nick */
    move(ypos, xpos);

    set_color((1 << 4)+3); addch('[');
    if (nickrec != NULL && (nickrec->op || nickrec->voice))
    {
        set_color((1 << 4)+15); addch(nickrec->op ? '@' : '+');
    }
    set_color((1 << 4)+7); addstr(nick);
    if (umode_size)
    {
        set_color((1 << 4)+15); addch('(');
        set_color((1 << 4)+3); addch('+');
        set_color((1 << 4)+7); addstr(server->usermode);
        set_color((1 << 4)+15); addch(')');
        if (server->usermode_away)
        {
            set_color((1 << 4)+7); addstr(" (");
            set_color((1 << 4)+10); addstr("zZzZ");
            set_color((1 << 4)+7); addch(')');
        }
    }
    set_color((1 << 4)+3); addch(']');
    screen_refresh();
}

static void sig_statusbar_nick_redraw(void)
{
	gui_statusbar_redraw(nick_tag);
}

/* redraw channel */
static void statusbar_channel(int xpos, int ypos, int size)
{
    WI_ITEM_REC *item;
    CHANNEL_REC *channel;
    SERVER_REC *server;
    gchar channame[21], window[MAX_INT_STRLEN], *mode;
    int size_needed;
    int mode_size;

    server = active_win == NULL ? NULL : active_win->active_server;

    ltoa(window, active_win == NULL ? 0 :
	 g_slist_index(windows, active_win)+1);

    item = active_win != NULL && irc_item_check(active_win->active) ?
	    active_win->active : NULL;
    if (item == NULL)
    {
	/* display server tag */
        channame[0] = '\0';
        mode = NULL;
	mode_size = 0;

	size_needed = 3 + strlen(window) + (server == NULL ? 0 : strlen(server->tag));
    }
    else
    {
	/* display channel + mode */
        strncpy(channame, item->name, 20); channame[20] = '\0';

	channel = irc_item_channel(item);
	if (channel == NULL) {
                mode_size = 0;
		mode = NULL;
	} else {
		mode = channel_get_mode(channel);
		mode_size = strlen(mode);
		if (mode_size > 0) mode_size += 3; /* (+) */
	}

	size_needed = 3 + strlen(window) + strlen(channame) + mode_size;
    }

    if (size != size_needed)
    {
        /* we need more (or less..) space! */
        gui_statusbar_resize(channel_tag, size_needed);
        if (mode != NULL) g_free(mode);
        return;
    }

    move(ypos, xpos);
    set_color((1 << 4)+3); addch('[');

    /* window number */
    set_color((1 << 4)+7); addstr(window);
    set_color((1 << 4)+3); addch(':');

    if (channame[0] == '\0' && server != NULL)
    {
	/* server tag */
	set_color((1 << 4)+7); addstr(server->tag);
    }
    else if (channame[0] != '\0')
    {
	/* channel + mode */
	set_color((1 << 4)+7); addstr(channame);
	if (mode_size)
	{
	    set_color((1 << 4)+15); addch('(');
	    set_color((1 << 4)+3); addch('+');
	    set_color((1 << 4)+7); addstr(mode);
	    set_color((1 << 4)+15); addch(')');
	}
    }
    set_color((1 << 4)+3); addch(']');
    screen_refresh();

    if (mode != NULL) g_free(mode);
}

static void sig_statusbar_channel_redraw(void)
{
	gui_statusbar_redraw(channel_tag);
}

static void draw_activity(gchar *title, gboolean act, gboolean det)
{
    WINDOW_REC *window;
    GList *tmp;
    gchar str[(sizeof(int) * CHAR_BIT + 2) / 3 + 1];
    gboolean first, is_det;

    set_color((1 << 4)+7); addstr(title);

    first = TRUE;
    for (tmp = activity_list; tmp != NULL; tmp = tmp->next)
    {
	window = tmp->data;

	is_det = window->new_data == NEWDATA_MSG_FORYOU;
	if (is_det && !det) continue;
	if (!is_det && !act) continue;

	if (first)
	    first = FALSE;
	else
	{
	    set_color((1 << 4)+3);
	    addch(',');
	}

	sprintf(str, "%d", g_slist_index(windows, window)+1);
	switch (window->new_data)
	{
	    case NEWDATA_TEXT:
		set_color((1 << 4)+3);
		break;
	    case NEWDATA_MSG:
		set_color((1 << 4)+15);
		break;
	    case NEWDATA_MSG_FORYOU:
		set_color((1 << 4)+13);
		break;
	}
	addstr(str);
    }
}

/* redraw activity */
static void statusbar_activity(int xpos, int ypos, int size)
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

	size_needed += 1+g_snprintf(str, sizeof(str), "%d", g_slist_index(windows, window)+1);

	if (!use_colors && window->new_data == NEWDATA_MSG_FORYOU)
	    det = TRUE;
	else
	    act = TRUE;
    }

    if (act) size_needed += 6; /* [Act: ], -1 */
    if (det) size_needed += 6; /* [Det: ], -1 */
    if (act && det) size_needed--;

    if (size != size_needed)
    {
        /* we need more (or less..) space! */
        gui_statusbar_resize(activity_tag, size_needed);
        return;
    }

    if (size == 0)
        return;

    move(ypos, xpos);
    set_color((1 << 4)+3); addch('[');
    if (act) draw_activity("Act: ", TRUE, !det);
    if (act && det) addch(' ');
    if (det) draw_activity("Det: ", FALSE, TRUE);
    set_color((1 << 4)+3); addch(']');

    screen_refresh();
}

static void sig_statusbar_activity_hilight(WINDOW_REC *window, gpointer oldlevel)
{
    int pos, inspos;
    GList *tmp;

    g_return_if_fail(window != NULL);

    if (settings_get_bool("toggle_actlist_moves"))
    {
	/* Move the window to the first in the activity list */
	if (g_list_find(activity_list, window) != NULL)
	    activity_list = g_list_remove(activity_list, window);
	if (window->new_data != 0)
	    activity_list = g_list_prepend(activity_list, window);
	gui_statusbar_redraw(activity_tag);
	return;
    }

    if (g_list_find(activity_list, window) != NULL)
    {
	/* already in activity list */
	if (window->new_data == 0)
	{
	    /* remove from activity list */
	    activity_list = g_list_remove(activity_list, window);
	    gui_statusbar_redraw(activity_tag);
	}
	else if (window->new_data != GPOINTER_TO_INT(oldlevel))
	{
	    /* different level as last time, just redraw it. */
	    gui_statusbar_redraw(activity_tag);
	}
        return;
    }

    if (window->new_data == 0)
	    return;

    /* add window to activity list .. */
    pos = g_slist_index(windows, window);

    inspos = 0;
    for (tmp = activity_list; tmp != NULL; tmp = tmp->next, inspos++)
    {
	if (pos < g_slist_index(windows, tmp->data))
	{
	    activity_list = g_list_insert(activity_list, window, inspos);
	    break;
	}
    }
    if (tmp == NULL)
	activity_list = g_list_append(activity_list, window);

    gui_statusbar_redraw(activity_tag);
}

static void sig_statusbar_activity_window_destroyed(WINDOW_REC *window)
{
    g_return_if_fail(window != NULL);

    if (g_list_find(activity_list, window) != NULL)
    {
        activity_list = g_list_remove(activity_list, window);
        gui_statusbar_redraw(activity_tag);
    }
}

/* redraw -- more -- */
static void statusbar_more(int xpos, int ypos, int size)
{
    if (size != 10) return;

    move(ypos, xpos);
    set_color((1 << 4)+15); addstr("-- more --");
    screen_refresh();
}

static void sig_statusbar_more_check_remove(WINDOW_REC *window)
{
    g_return_if_fail(window != NULL);

    if (!is_window_visible(window))
        return;

    if (more_tag != -1 && WINDOW_GUI(window)->bottom)
    {
        gui_statusbar_remove(more_tag);
        more_tag = -1;
    }
}

static void sig_statusbar_more_check(WINDOW_REC *window)
{
    g_return_if_fail(window != NULL);

    if (WINDOW_GUI(window)->parent->active != window)
        return;

    if (!WINDOW_GUI(window)->bottom)
    {
        if (more_tag == -1)
            more_tag = gui_statusbar_allocate(10, FALSE, FALSE, 0, statusbar_more);
    }
    else if (more_tag != -1)
    {
        gui_statusbar_remove(more_tag);
        more_tag = -1;
    }
}

static void statusbar_lag(int xpos, int ypos, int size)
{
	IRC_SERVER_REC *server;
	GString *str;
	int size_needed, lag_unknown;
	time_t now;

	now = time(NULL);
	str = g_string_new(NULL);

	server = (IRC_SERVER_REC *) (active_win == NULL ? NULL : active_win->active_server);
	if (server == NULL || server->lag_last_check == 0)
		size_needed = 0;
	else if (server->lag_sent == 0 || now-server->lag_sent < 5) {
                lag_unknown = now-server->lag_last_check > MAX_LAG_UNKNOWN_TIME;

		if (server->lag < lag_min_show && !lag_unknown)
			size_needed = 0; /* small lag, don't display */
		else {
			g_string_sprintf(str, "%d.%02d", server->lag/1000, (server->lag % 1000)/10);
			if (lag_unknown)
				g_string_append(str, " (??)");
			size_needed = str->len+7;
		}
	} else {
		/* big lag, still waiting .. */
		g_string_sprintf(str, "%ld (??)", now-server->lag_sent);
		size_needed = str->len+7;
	}

    if (size != size_needed)
    {
        /* we need more (or less..) space! */
        gui_statusbar_resize(lag_tag, size_needed);
        g_string_free(str, TRUE);
        return;
    }

    if (size != 0)
    {
	lag_last_draw = now;
	move(ypos, xpos);
	set_color((1 << 4)+3); addch('[');
	set_color((1 << 4)+7); addstr("Lag: ");

	set_color((1 << 4)+15); addstr(str->str);
	set_color((1 << 4)+3); addch(']');

	screen_refresh();
    }
    g_string_free(str, TRUE);
}

static void sig_statusbar_lag_redraw(void)
{
	gui_statusbar_redraw(lag_tag);
}

static int statusbar_lag_timeout(void)
{
	/* refresh statusbar every 10 seconds */
	if (time(NULL)-lag_last_draw < LAG_REFRESH_TIME)
		return 1;

	gui_statusbar_redraw(lag_tag);
	return 1;
}

static void statusbar_topic(int xpos, int ypos, int size)
{
	CHANNEL_REC *channel;
	QUERY_REC *query;
	char *str, *topic;

	if (size != COLS-2) {
		/* get all space for topic */
		gui_statusbar_resize(topic_tag, COLS-2);
		return;
	}

	move(ypos, xpos);
	set_bg((1<<4)+7); clrtoeol(); set_bg(0);

	if (active_win == NULL)
		return;

	topic = NULL;
	channel = irc_item_channel(active_win->active);
	query = irc_item_query(active_win->active);
	if (channel != NULL && channel->topic != NULL) topic = channel->topic;
	if (query != NULL && query->address != NULL) topic = query->address;
	if (topic == NULL) return;

	str = g_strdup_printf("%.*s", size, topic);
	set_color((1<<4)+15); addstr(str);
	g_free(str);

	screen_refresh();
}

static void sig_statusbar_topic_redraw(void)
{
	gui_statusbar_redraw(topic_tag);
}

static void read_settings(void)
{
	int ypos;

	if (topic_tag == -1 && settings_get_bool("toggle_show_topicbar")) {
		ypos = gui_statusbar_create(TRUE);
		topic_tag = gui_statusbar_allocate(0, FALSE, TRUE, ypos, statusbar_topic);
		signal_add("window changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
		signal_add("window item changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
		signal_add("channel topic changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
		signal_add("query address changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
	} else if (topic_tag != -1 && !settings_get_bool("toggle_show_topicbar")) {
		gui_statusbar_delete(TRUE, 0);
		topic_tag = -1;
		signal_remove("window changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
		signal_remove("window item changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
		signal_remove("channel topic changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
		signal_remove("query address changed", (SIGNAL_FUNC) sig_statusbar_topic_redraw);
	}

	lag_min_show = settings_get_int("lag_min_show")*10;
}

void gui_statusbar_items_init(void)
{
	settings_add_int("misc", "lag_min_show", 100);

	/* clock */
	clock_tag = gui_statusbar_allocate(7, FALSE, FALSE, 0, statusbar_clock);
	clock_timetag = g_timeout_add(1000, (GSourceFunc) statusbar_clock_timeout, NULL);

	/* nick */
	nick_tag = gui_statusbar_allocate(2, FALSE, FALSE, 0, statusbar_nick);
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
	channel_tag = gui_statusbar_allocate(2, FALSE, FALSE, 0, statusbar_channel);
	signal_add("window changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw);
	signal_add("window item changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw);
	signal_add("channel mode changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw);
	signal_add("window server changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw);

	/* activity */
	activity_list = NULL;
	activity_tag = gui_statusbar_allocate(0, FALSE, FALSE, 0, statusbar_activity);
	signal_add("window activity", (SIGNAL_FUNC) sig_statusbar_activity_hilight);
	signal_add("window destroyed", (SIGNAL_FUNC) sig_statusbar_activity_window_destroyed);

	/* more */
	more_tag = -1;
	signal_add("gui page scrolled", (SIGNAL_FUNC) sig_statusbar_more_check_remove);
	signal_add("window item changed", (SIGNAL_FUNC) sig_statusbar_more_check);
	signal_add("gui print text", (SIGNAL_FUNC) sig_statusbar_more_check);

	/* lag */
	lag_tag = gui_statusbar_allocate(0, FALSE, FALSE, 0, statusbar_lag);
	lag_timetag = g_timeout_add(1000*LAG_REFRESH_TIME, (GSourceFunc) statusbar_lag_timeout, NULL);
	signal_add("server lag", (SIGNAL_FUNC) sig_statusbar_lag_redraw);
	signal_add("window server changed", (SIGNAL_FUNC) sig_statusbar_lag_redraw);

	/* topic bar */
	topic_tag = -1;
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);

	read_settings();
}

void gui_statusbar_items_deinit(void)
{
	/* clock */
	gui_statusbar_remove(clock_tag);

	/* nick */
	gui_statusbar_remove(nick_tag);
	g_source_remove(clock_timetag);
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
	gui_statusbar_remove(channel_tag);
	signal_remove("window changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw);
	signal_remove("window item changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw);
	signal_remove("channel mode changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw);
	signal_remove("window server changed", (SIGNAL_FUNC) sig_statusbar_channel_redraw);

	/* activity */
	gui_statusbar_remove(activity_tag);
	signal_remove("window activity", (SIGNAL_FUNC) sig_statusbar_activity_hilight);
	signal_remove("window destroyed", (SIGNAL_FUNC) sig_statusbar_activity_window_destroyed);
	g_list_free(activity_list);

	/* more */
	if (more_tag != -1) gui_statusbar_remove(more_tag);
	signal_remove("gui page scrolled", (SIGNAL_FUNC) sig_statusbar_more_check_remove);
	signal_remove("window item changed", (SIGNAL_FUNC) sig_statusbar_more_check);
	signal_remove("gui print text", (SIGNAL_FUNC) sig_statusbar_more_check);

	/* lag */
	gui_statusbar_remove(lag_tag);
	g_source_remove(lag_timetag);
	signal_remove("server lag", (SIGNAL_FUNC) sig_statusbar_lag_redraw);
	signal_remove("window server changed", (SIGNAL_FUNC) sig_statusbar_lag_redraw);

	/* topic */
	if (topic_tag != -1) gui_statusbar_delete(TRUE, 0);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
