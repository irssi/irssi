MODULE = Irssi  PACKAGE = Irssi

void
windows()
PREINIT:
	GSList *tmp;
        HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Window", 0);
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		push_bless(tmp->data, stash);
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
	printtext_string(NULL, NULL, level, str);

void
command(cmd)
	char *cmd
CODE:
	perl_command(cmd, active_win->active_server, active_win->active);

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
window_find_item(name)
	char *name
CODE:
	RETVAL = window_find_item(NULL, name);
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

Irssi::Windowitem
window_item_find(name)
	char *name
CODE:
	RETVAL = window_item_find(NULL, name);
OUTPUT:
	RETVAL


#*******************************
MODULE = Irssi	PACKAGE = Irssi::Server
#*******************************

void
command(server, cmd)
	Irssi::Server server
	char *cmd
CODE:
	perl_command(cmd, server, active_win->active);

void
print(server, channel, str, level)
	Irssi::Server server
	char *channel
	char *str
	int level
CODE:
	printtext_string(server, channel, level, str);

Irssi::Windowitem
window_item_find(server, name)
	Irssi::Server server
	char *name

Irssi::Window
window_find_item(server, name)
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
items(window)
	Irssi::Window window
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
                CHANNEL_REC *rec = tmp->data;

		XPUSHs(sv_2mortal(irssi_bless(rec)));
	}

void
print(window, str, level=MSGLEVEL_CLIENTNOTICE)
	Irssi::Window window
	char *str
        int level;
CODE:
	printtext_window(window, level, str);

void
command(window, cmd)
	Irssi::Window window
	char *cmd
CODE:
	perl_command(cmd, window->active_server, window->active);

void
window_item_add(window, item, automatic)
	Irssi::Window window
	Irssi::Windowitem item
	int automatic

void
window_item_remove(item)
	Irssi::Windowitem item

void
window_item_destroy(item)
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
MODULE = Irssi	PACKAGE = Irssi::Windowitem  PREFIX = window_item_
#*******************************

void
print(item, str, level=MSGLEVEL_CLIENTNOTICE)
	Irssi::Windowitem item
	int level
	char *str
CODE:
	printtext_string(item->server, item->name, level, str);

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

void
window_item_set_active(item)
	Irssi::Windowitem item
CODE:
	window_item_set_active(window_item_window(item), item);
