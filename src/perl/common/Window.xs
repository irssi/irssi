MODULE = Irssi  PACKAGE = Irssi

void
windows()
PREINIT:
	GSList *tmp;
        HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Window", 0);
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
                WINDOW_REC *rec = tmp->data;

		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(rec))), stash)));
	}


Irssi::Window
active_win()
CODE:
	RETVAL = active_win;
OUTPUT:
	RETVAL

Irssi::Server
active_server()
CODE:
	RETVAL = active_win->active_server;
OUTPUT:
	RETVAL

void
print(str, level=MSGLEVEL_CLIENTNOTICE)
	char *str
        int level;
CODE:
	printtext(NULL, NULL, level, str);

void
print_window(str, level=MSGLEVEL_CLIENTNOTICE)
	char *str
        int level;
CODE:
	printtext_window(active_win, level, str);

void
command(cmd, server=active_win->active_server, item=active_win->active)
	char *cmd
	Irssi::Server server
	Irssi::Windowitem item
CODE:
	perl_command(cmd, server, item);

Irssi::Window
window_find_name(name)
	char *name

Irssi::Window
window_find_refnum(refnum)
	int refnum

int
window_refnum_prev(refnum, wrap)
	int refnum
	int wrap

int
window_refnum_next(refnum, wrap)
	int refnum
	int wrap

int
windows_refnum_last()

Irssi::Window
window_find_level(level)
	int level
CODE:
	RETVAL = window_find_level(NULL, level);
OUTPUT:
	RETVAL

Irssi::Window
window_find_closest(name, level)
	char *name
	int level
CODE:
	RETVAL = window_find_closest(NULL, name, level);
OUTPUT:
	RETVAL


#*******************************
MODULE = Irssi	PACKAGE = Irssi::Server
#*******************************

void
command(server, cmd, item=active_win->active)
	Irssi::Server server
	char *cmd
	Irssi::Windowitem item
CODE:
	if (item != NULL && item->server != SERVER(server))
		item = NULL;
	perl_command(cmd, server, item);

void
print(server, channel, str, level)
	Irssi::Server server
	char *channel
	int level
	char *str
CODE:
	printtext(server, channel, level, str);

Irssi::Windowitem
window_item_find(server, name)
	Irssi::Server server
	char *name

Irssi::Window
window_find_level(server, level)
	Irssi::Server server
	int level

Irssi::Window
window_find_closest(server, name, level)
	Irssi::Server server
	char *name
	int level


#*******************************
MODULE = Irssi	PACKAGE = Irssi::Window  PREFIX=window_
#*******************************

void
values(window)
	Irssi::Window window
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "refnum", 6, newSViv(window->refnum), 0);
	hv_store(hv, "name", 4, new_pv(window->name), 0);

	if (window->active) {
		hv_store(hv, "active", 6, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(window->active))),
						   irssi_get_stash(window->active)), 0);
	}
	if (window->active_server) {
		hv_store(hv, "active_server", 13, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(window->active_server))),
							   irssi_get_stash(window->active_server)), 0);
        }

	hv_store(hv, "lines", 5, newSViv(window->lines), 0);

	hv_store(hv, "level", 5, newSViv(window->level), 0);
	hv_store(hv, "new_data", 8, newSViv(window->new_data), 0);
	hv_store(hv, "last_color", 10, newSViv(window->last_color), 0);
	hv_store(hv, "last_timestamp", 14, newSViv(window->last_timestamp), 0);
	hv_store(hv, "last_line", 9, newSViv(window->last_line), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

void
items(window)
	Irssi::Window window
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
                CHANNEL_REC *rec = tmp->data;

		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(rec))),
					   irssi_get_stash(rec))));
	}

void
command(window, cmd, server=window->active_server, item=window->active)
	Irssi::Window window
	char *cmd
	Irssi::Server server
	Irssi::Windowitem item
CODE:
	perl_command(cmd, server, item);

void
window_item_add(window, item, automatic)
	Irssi::Window window
	Irssi::Windowitem item
	int automatic

void
window_item_remove(window, item)
	Irssi::Window window
	Irssi::Windowitem item

void
window_item_destroy(window, item)
	Irssi::Window window
	Irssi::Windowitem item

void
window_item_set_active(window, item)
	Irssi::Window window
	Irssi::Windowitem item

void
window_item_prev(window)
	Irssi::Window window

void
window_item_next(window)
	Irssi::Window window

void
window_destroy(window)
	Irssi::Window window

void
window_set_active(window)
	Irssi::Window window

void
window_change_server(window, server)
	Irssi::Window window
	Irssi::Server server

void
window_set_refnum(window, refnum)
	Irssi::Window window
	int refnum

void
window_set_name(window, name)
	Irssi::Window window
	char *name

void
window_set_level(window, level)
	Irssi::Window window
	int level

char *
window_get_active_name(window)
	Irssi::Window window

Irssi::Window
window_find_item(server, name)
	Irssi::Server server
	char *name

Irssi::Windowitem
window_item_find(window, server, name)
	Irssi::Window window
	Irssi::Server server
	char *name
CODE:
	RETVAL = window_item_find_window(window, server, name);
OUTPUT:
	RETVAL

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Windowitem
#*******************************

void
values(item)
	Irssi::Windowitem item
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "server", 6, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(item->server))),
					   irssi_get_stash(item->server)), 0);
	hv_store(hv, "name", 4, new_pv(item->name), 0);
	hv_store(hv, "new_data", 8, newSViv(item->new_data), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

void
command(item, cmd)
	Irssi::Windowitem item
	char *cmd
CODE:
	perl_command(cmd, item->server, item);

Irssi::Window
window_create(item, automatic)
	Irssi::Windowitem item
	int automatic

void
window_item_create(item, automatic)
	Irssi::Windowitem item
	int automatic

Irssi::Window
window(item)
	Irssi::Windowitem item
CODE:
	RETVAL = window_item_window(item);
OUTPUT:
	RETVAL

void
window_item_change_server(item, server)
	Irssi::Windowitem item
	Irssi::Server server

int
window_item_is_active(item)
	Irssi::Windowitem item


#*******************************
MODULE = Irssi	PACKAGE = Irssi::Windowitem
#*******************************

void
print(item, str, level=MSGLEVEL_CLIENTNOTICE)
	Irssi::Windowitem item
	int level
	char *str
CODE:
	printtext(item->server, item->name, level, str);
