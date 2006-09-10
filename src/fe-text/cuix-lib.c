#include "module.h"
#include "settings.h"
#include "cuix-lib.h"
#include "signals.h"
#include "irc.h"
#include "irc-channels.h"
#include "mode-lists.h"
#include "gui-windows.h"


int do_nothing (char *foo)
{
    (void)foo;
    return 0;
}


void display_message (char *message)
{
    object *list;
    entry *text, *entries[2];

    text = create_label (message);
    entries[0] = text;
    entries[1] = NULL;
    list = create_list ("Message", entries);
    display_object (list);
}


int change_nick (char *nick)
{
    SERVER_REC *server;
    WI_ITEM_REC *wiitem;
    if (active_win == NULL) {
        server = NULL;
        wiitem = NULL;
    } else {
        server = active_win->active_server != NULL ?
            active_win->active_server : active_win->connect_server;
        wiitem = active_win->active;
    } 
    signal_emit("command nick", 3, nick, server, wiitem);
    return 0;
}



int show_banlist (char *nothing)
{
    GSList *tmp;
    IRC_CHANNEL_REC *chan = IRC_CHANNEL(active_win->active);
    BAN_REC *ban;
    object *list;
    entry *entry, **entries;
    unsigned int size, i;
    GString **baninfo;

    if (!chan) {
        display_message ("This is not a channel");
        return 1;
    }
    if (!chan->banlist) {
        display_message ("No bans set");
        return 0;
    }

    size = (unsigned int) g_slist_length (chan->banlist);
    entries = g_new0 (struct entry *, size + 1);
    baninfo = g_new0 (GString *, size);

    for (tmp = chan->banlist, i = 0; tmp; tmp = tmp->next, i++) {
        ban = tmp->data;
        baninfo[i] = g_string_new (NULL);
        g_string_sprintf (baninfo[i], "%s set by %s %d seconds ago", ban->ban, ban->setby, (int)(time(NULL)-ban->time));
        entry = create_label (baninfo[i]->str);
        entries[i] = entry;
    }

    list = create_list ("Bans", entries);
    display_object (list);
    for (i = 0; i < size; i++) {
        g_string_free (baninfo[i], FALSE);
    }
    g_free (entries);
    g_free (baninfo);

    return 0;
}


int change_nick_form (char *nothing) {
    object *form;
    entry *question, *answer;
    (void)nothing;

    form = create_form ("True!");
    question = create_label ("Enter your new nick");
    answer = create_field ("", change_nick);
    attach_entry (form, question);
    attach_entry (form, answer);
    display_object (form);
    return 0;
}


int about_list (char *nothing) 
{
    (void)nothing;

    display_message ("(c) irssi; See http://www.irssi.org.");
    return 0;
}




int home_menu (char *nothing) 
{
    /* Objects declaration */
    object *root_menu;
    entry *about, *banlist, *nick;
    (void)nothing;

    /* Objects initialisation */
    root_menu = create_menu ("My root menu");
    banlist = create_menuentry ("Banlist", show_banlist);
    nick = create_menuentry ("Change nick", change_nick_form);
    about = create_menuentry ("About", about_list);

    /* Layout */
    attach_entry (root_menu, (void *)banlist);
    attach_entry (root_menu, (void *)nick);
    attach_entry (root_menu, (void *)about);

    /* Declare that the object is ready to be displayed and do it */
    display_object (root_menu);
    return 0;
}
