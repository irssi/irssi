MODULE = Irssi  PACKAGE = Irssi

void
channels()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = channels; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(irssi_bless((CHANNEL_REC *) tmp->data)));
	}

Irssi::Channel
channel_find(channel)
	char *channel
CODE:
	RETVAL = channel_find(NULL, channel);
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
PPCODE:
	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(irssi_bless((CHANNEL_REC *) tmp->data)));
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

void
nicklist_get_same(server, nick)
	Irssi::Server server
        char *nick
PREINIT:
	GSList *list, *tmp;
PPCODE:
	list = nicklist_get_same(server, nick);

	for (tmp = list; tmp != NULL; tmp = tmp->next->next) {
		XPUSHs(sv_2mortal(irssi_bless((CHANNEL_REC *) tmp->data)));
		XPUSHs(sv_2mortal(irssi_bless((NICK_REC *) tmp->next->data)));
	}
	g_slist_free(list);

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Channel  PREFIX = channel_
#*******************************

void
init(channel)
	Irssi::Channel channel
CODE:
	perl_channel_fill_hash(hvref(ST(0)), channel);

void
channel_destroy(channel)
	Irssi::Channel channel

void
command(channel, cmd)
	Irssi::Channel channel
	char *cmd
CODE:
	signal_emit("send command", 3, cmd, channel->server, channel);

Irssi::Nick
nick_insert(channel, nick, op, voice, send_massjoin)
	Irssi::Channel channel
	char *nick
	int op
	int voice
	int send_massjoin
CODE:
	RETVAL = nicklist_insert(channel, nick, op, voice, send_massjoin);
OUTPUT:
	RETVAL

void
nick_remove(channel, nick)
	Irssi::Channel channel
	Irssi::Nick nick
CODE:
	nicklist_remove(channel, nick);

Irssi::Nick
nick_find(channel, mask)
	Irssi::Channel channel
	char *mask
CODE:
	RETVAL = nicklist_find(channel, mask);
OUTPUT:
	RETVAL

void
nicks(channel)
	Irssi::Channel channel
PREINIT:
	GSList *list, *tmp;
PPCODE:
	list = nicklist_getnicks(channel);

	for (tmp = list; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(irssi_bless((NICK_REC *) tmp->data)));
	}
	g_slist_free(list);

#*******************************
MODULE = Irssi	PACKAGE = Irssi::Nick
#*******************************

void
init(nick)
	Irssi::Nick nick
CODE:
	perl_nick_fill_hash(hvref(ST(0)), nick);

