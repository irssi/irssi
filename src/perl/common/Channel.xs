MODULE = Irssi  PACKAGE = Irssi

void
channels()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = channels; tmp != NULL; tmp = tmp->next) {
                CHANNEL_REC *rec = tmp->data;

		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(rec))),
					   irssi_get_stash(rec))));
	}

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Server
#*******************************

void
channels(server)
	Irssi::Server server
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
                CHANNEL_REC *rec = tmp->data;

		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(rec))),
					   irssi_get_stash(rec))));
	}

Irssi::Channel
channel_create(chat_type, server, name, automatic)
	int chat_type
	Irssi::Server server
	char *name
	int automatic

Irssi::Channel
channel_find(server, name)
	Irssi::Server server
	char *name

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Channel  PREFIX = channel_
#*******************************

void
values(channel)
	Irssi::Channel channel
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	perl_channel_fill_hash(hv, channel);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

void
channel_destroy(channel)
	Irssi::Channel channel

Irssi::Channel
channel_find(channel)
	char *channel
CODE:
	RETVAL = channel_find(NULL, channel);
OUTPUT:
	RETVAL

void
command(channel, cmd)
	Irssi::Channel channel
	char *cmd
CODE:
	signal_emit("send command", 3, cmd, channel->server, channel);

Irssi::Nick
nicklist_insert(channel, nick, op, voice, send_massjoin)
	Irssi::Channel channel
	char *nick
	int op
	int voice
	int send_massjoin

void
nicklist_remove(channel, nick)
	Irssi::Channel channel
	Irssi::Nick nick

Irssi::Nick
nicklist_find(channel, mask)
	Irssi::Channel channel
	char *mask

void
nicklist_getnicks(channel)
	Irssi::Channel channel
PREINIT:
	GSList *list, *tmp;
	HV *stash;
PPCODE:
	list = nicklist_getnicks(channel);

	stash = gv_stashpv("Irssi::Nick", 0);
	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}
	g_slist_free(list);

void
nicklist_get_same(server, nick)
	Irssi::Server server
        char *nick
PREINIT:
	GSList *list, *tmp;
	HV *nickstash;
PPCODE:
	list = nicklist_get_same(server, nick);

	nickstash = gv_stashpv("Irssi::Nick", 0);
	for (tmp = list; tmp != NULL; tmp = tmp->next->next) {
		CHANNEL_REC *channel = tmp->data;

		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(channel))),
					   irssi_get_stash(channel))));
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->next->data))), nickstash)));
	}
	g_slist_free(list);

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Nick
#*******************************

void
values(nick)
	Irssi::Nick nick
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "last_check", 10, newSViv(nick->last_check), 0);

	hv_store(hv, "nick", 4, new_pv(nick->nick), 0);
	hv_store(hv, "host", 4, new_pv(nick->host), 0);
	hv_store(hv, "realname", 8, new_pv(nick->realname), 0);
	hv_store(hv, "hops", 4, newSViv(nick->hops), 0);

	hv_store(hv, "gone", 4, newSViv(nick->gone), 0);
	hv_store(hv, "serverop", 8, newSViv(nick->serverop), 0);

	hv_store(hv, "send_massjoin", 13, newSViv(nick->send_massjoin), 0);
	hv_store(hv, "op", 2, newSViv(nick->op), 0);
	hv_store(hv, "halfop", 6, newSViv(nick->halfop), 0);
	hv_store(hv, "voice", 5, newSViv(nick->voice), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

