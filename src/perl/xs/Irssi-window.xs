MODULE = Irssi  PACKAGE = Irssi

void
command(cmd, server=active_win->active_server, item=active_win->active)
	char *cmd
	Irssi::Server server
	Irssi::Windowitem item
CODE:
	signal_emit("send command", 3, cmd, server, item);

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
print(str)
	char *str
CODE:
	printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE, str);


#*******************************
MODULE = Irssi	PACKAGE = Irssi::Server
#*******************************

void
command(server, cmd, item=active_win->active)
	char *cmd
	Irssi::Server server
	Irssi::Windowitem item
CODE:
	if (item != NULL && item->server != server)
		item = NULL;
	signal_emit("send command", 3, cmd, server, item);

void
printtext(server, channel, level, str)
	Irssi::Server server
	char *channel
	int level
	char *str
CODE:
	printtext(server, channel, level, str);

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Window
#*******************************

void
values(window)
	Irssi::Window window
PREINIT:
        HV *hv, *stash;
	AV *av;
	GSList *tmp;
PPCODE:
	hv = newHV();
	hv_store(hv, "refnum", 6, newSViv(window->refnum), 0);
	hv_store(hv, "name", 4, new_pv(window->name), 0);

	av = newAV();
	for (tmp = window->items; tmp != NULL; tmp = tmp->next) {
		av_push(av, new_pv(tmp->data));
	}
	hv_store(hv, "items", 8, newRV_noinc((SV*)av), 0);

	stash = gv_stashpv("Irssi::Windowitem", 0);
	hv_store(hv, "active", 6, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(window->active))), stash), 0);
	stash = gv_stashpv("Irssi::Server", 0);
	hv_store(hv, "active_server", 13, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(window->active_server))), stash), 0);

	hv_store(hv, "lines", 5, newSViv(window->lines), 0);

	hv_store(hv, "level", 5, newSViv(window->level), 0);
	hv_store(hv, "new_data", 8, newSViv(window->new_data), 0);
	hv_store(hv, "last_timestamp", 14, newSViv(window->last_timestamp), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

void
command(window, cmd, server=window->active_server, item=window->active)
	Irssi::Window window
	char *cmd
	Irssi::Server server
	Irssi::Windowitem item
CODE:
	signal_emit("send command", 3, cmd, server, item);

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Windowitem
#*******************************

void
values(item)
	Irssi::Windowitem item
PREINIT:
        HV *hv, *stash;
	AV *av;
	GSList *tmp;
PPCODE:
	hv = newHV();
	stash = gv_stashpv("Irssi::Server", 0);
	hv_store(hv, "server", 6, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(item->server))), stash), 0);
	hv_store(hv, "name", 4, new_pv(item->name), 0);
	hv_store(hv, "new_data", 8, newSViv(item->new_data), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

void
command(item, cmd)
	Irssi::Windowitem item
	char *cmd
CODE:
	signal_emit("send command", 3, cmd, item->server, item);
