MODULE = Irssi  PACKAGE = Irssi

void
channels()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Channel", 0);
	for (tmp = channels; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

int
is_channel(text)
	char *text
CODE:
	RETVAL = ischannel(*text);
OUTPUT:
	RETVAL

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Server
#*******************************

void
channels(server)
	Irssi::Server server
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Channel", 0);
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

Irssi::Channel
channel_create(server, channel, automatic)
	Irssi::Server server
	char *channel
	int automatic

Irssi::Channel
channel_find(server, channel)
	Irssi::Server server
	char *channel

void
channels_join(server, data, automatic)
	Irssi::Server server
	char *data
	int automatic

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Channel  PREFIX = channel_
#*******************************

void
values(channel)
	Irssi::Channel channel
PREINIT:
        HV *hv, *stash;
	char *type;
PPCODE:
	type = "channel";

	hv = newHV();
	hv_store(hv, "type", 4, new_pv(type), 0);

	stash = gv_stashpv("Irssi::Server", 0);
	hv_store(hv, "server", 6, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(channel->server))), stash), 0);
	hv_store(hv, "name", 4, new_pv(channel->name), 0);

	hv_store(hv, "new_data", 8, newSViv(channel->new_data), 0);
	hv_store(hv, "createtime", 10, newSViv(channel->createtime), 0);

	hv_store(hv, "topic", 5, new_pv(channel->topic), 0);
	hv_store(hv, "limit", 5, newSViv(channel->limit), 0);
	hv_store(hv, "key", 3, new_pv(channel->key), 0);

	hv_store(hv, "chanop", 6, newSViv(channel->chanop), 0);

	hv_store(hv, "names_got", 9, newSViv(channel->names_got), 0);
	hv_store(hv, "wholist", 7, newSViv(channel->wholist), 0);
	hv_store(hv, "synced", 6, newSViv(channel->synced), 0);

	hv_store(hv, "left", 4, newSViv(channel->left), 0);
	hv_store(hv, "kicked", 6, newSViv(channel->kicked), 0);

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

char *
channel_get_mode(channel)
        Irssi::Channel channel

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
	HV *chanstash, *nickstash;
PPCODE:
	list = nicklist_get_same(server, nick);

	chanstash = gv_stashpv("Irssi::Channel", 0);
	nickstash = gv_stashpv("Irssi::Nick", 0);

	for (tmp = list; tmp != NULL; tmp = tmp->next->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), chanstash)));
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
	hv_store(hv, "send_massjoin", 13, newSViv(nick->send_massjoin), 0);

	hv_store(hv, "nick", 4, new_pv(nick->nick), 0);
	hv_store(hv, "host", 4, new_pv(nick->host), 0);
	hv_store(hv, "realname", 8, new_pv(nick->realname), 0);

	hv_store(hv, "hops", 4, newSViv(nick->hops), 0);

	hv_store(hv, "op", 2, newSViv(nick->op), 0);
	hv_store(hv, "voice", 5, newSViv(nick->voice), 0);
	hv_store(hv, "gone", 4, newSViv(nick->gone), 0);
	hv_store(hv, "ircop", 5, newSViv(nick->ircop), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

