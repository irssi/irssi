#include "module.h"

static void perl_irc_connect_fill_hash(HV *hv, IRC_SERVER_CONNECT_REC *conn)
{
	perl_connect_fill_hash(hv, (SERVER_CONNECT_REC *) conn);
	hv_store(hv, "alternate_nick", 14, new_pv(conn->alternate_nick), 0);
}

static void perl_irc_server_fill_hash(HV *hv, IRC_SERVER_REC *server)
{
       	perl_server_fill_hash(hv, server);

       	hv_store(hv, "real_address", 12, new_pv(server->real_address), 0);
       	hv_store(hv, "usermode", 8, new_pv(server->usermode), 0);
       	hv_store(hv, "userhost", 8, new_pv(server->userhost), 0);
}

static void perl_ban_fill_hash(HV *hv, BAN_REC *ban)
{
	hv_store(hv, "ban", 3, new_pv(ban->ban), 0);
	hv_store(hv, "setby", 5, new_pv(ban->setby), 0);
	hv_store(hv, "time", 4, newSViv(ban->time), 0);
}

static void perl_dcc_fill_hash(HV *hv, DCC_REC *dcc)
{
	HV *stash;

	hv_store(hv, "type", 4, new_pv((char *) dcc_type2str(dcc->type)), 0);
	hv_store(hv, "created", 7, newSViv(dcc->created), 0);

	hv_store(hv, "server", 6, irssi_bless(dcc->server), 0);
	hv_store(hv, "nick", 4, new_pv(dcc->nick), 0);

	stash = gv_stashpv("Irssi::Irc::Dcc", 0);
	hv_store(hv, "chat", 4, new_bless(dcc->chat, stash), 0);

	hv_store(hv, "ircnet", 6, new_pv(dcc->ircnet), 0);
	hv_store(hv, "mynick", 6, new_pv(dcc->mynick), 0);

	hv_store(hv, "arg", 3, new_pv(dcc->arg), 0);
	hv_store(hv, "file", 4, new_pv(dcc->file), 0);

	hv_store(hv, "addr", 4, new_pv(dcc->addrstr), 0);
	hv_store(hv, "port", 4, newSViv(dcc->port), 0);

	hv_store(hv, "size", 4, newSViv(dcc->size), 0);
	hv_store(hv, "transfd", 7, newSViv(dcc->transfd), 0);
	hv_store(hv, "skipped", 7, newSViv(dcc->skipped), 0);
	hv_store(hv, "starttime", 9, newSViv(dcc->starttime), 0);
}

static void perl_netsplit_fill_hash(HV *hv, NETSPLIT_REC *netsplit)
{
        AV *av;
	HV *stash;
        GSList *tmp;

	hv_store(hv, "nick", 4, new_pv(netsplit->nick), 0);
	hv_store(hv, "address", 7, new_pv(netsplit->address), 0);
	hv_store(hv, "destroy", 7, newSViv(netsplit->destroy), 0);

	stash = gv_stashpv("Irssi::Irc::Netsplitserver", 0);
	hv_store(hv, "server", 6, new_bless(netsplit->server, stash), 0);

	stash = gv_stashpv("Irssi::Irc::Netsplitchannel", 0);
	av = newAV();
	for (tmp = netsplit->channels; tmp != NULL; tmp = tmp->next) {
		av_push(av, sv_2mortal(new_bless(tmp->data, stash)));
	}
	hv_store(hv, "channels", 7, newRV_noinc((SV*)av), 0);
}

static void perl_netsplit_server_fill_hash(HV *hv, NETSPLIT_SERVER_REC *rec)
{
	hv_store(hv, "server", 6, new_pv(rec->server), 0);
	hv_store(hv, "destserver", 10, new_pv(rec->destserver), 0);
	hv_store(hv, "count", 5, newSViv(rec->count), 0);
}

static void perl_netsplit_channel_fill_hash(HV *hv, NETSPLIT_CHAN_REC *rec)
{
	hv_store(hv, "name", 4, new_pv(rec->name), 0);
	hv_store(hv, "nick", 4, irssi_bless(&rec->nick), 0);
}

static void perl_autoignore_fill_hash(HV *hv, AUTOIGNORE_REC *ai)
{
	hv_store(hv, "nick", 4, new_pv(ai->nick), 0);
	hv_store(hv, "timeleft", 8, newSViv(ai->timeleft), 0);
	hv_store(hv, "level", 5, newSViv(ai->level), 0);
}

static void perl_notifylist_fill_hash(HV *hv, NOTIFYLIST_REC *notify)
{
	AV *av;
	char **tmp;

	hv_store(hv, "mask", 4, new_pv(notify->mask), 0);
	hv_store(hv, "away_check", 10, newSViv(notify->away_check), 0);
	hv_store(hv, "idle_check_time", 15, newSViv(notify->idle_check_time), 0);

	av = newAV();
	for (tmp = notify->ircnets; *tmp != NULL; tmp++) {
		av_push(av, new_pv(*tmp));
	}
	hv_store(hv, "ircnets", 7, newRV_noinc((SV*)av), 0);
}

static PLAIN_OBJECT_INIT_REC irc_plains[] = {
	{ "Irssi::Irc::Ban", (PERL_OBJECT_FUNC) perl_ban_fill_hash },
	{ "Irssi::Irc::Dcc", (PERL_OBJECT_FUNC) perl_dcc_fill_hash },
	{ "Irssi::Irc::Netsplit", (PERL_OBJECT_FUNC) perl_netsplit_fill_hash },
	{ "Irssi::Irc::Netsplitserver", (PERL_OBJECT_FUNC) perl_netsplit_server_fill_hash },
	{ "Irssi::Irc::Netsplitchannel", (PERL_OBJECT_FUNC) perl_netsplit_channel_fill_hash },
	{ "Irssi::Irc::Autoignore", (PERL_OBJECT_FUNC) perl_autoignore_fill_hash },
	{ "Irssi::Irc::Notifylist", (PERL_OBJECT_FUNC) perl_notifylist_fill_hash },

	{ NULL, NULL }
};

MODULE = Irssi::Irc  PACKAGE = Irssi::Irc

PROTOTYPES: ENABLE

void
init()
PREINIT:
	static int initialized = FALSE;
	int chat_type;
CODE:
	if (initialized) return;
	initialized = TRUE;

	chat_type = chat_protocol_lookup("IRC");

	irssi_add_object(module_get_uniq_id("SERVER CONNECT", 0),
			 chat_type, "Irssi::Irc::Connect",
			 (PERL_OBJECT_FUNC) perl_irc_connect_fill_hash);
	irssi_add_object(module_get_uniq_id("SERVER", 0),
			 chat_type, "Irssi::Irc::Server",
			 (PERL_OBJECT_FUNC) perl_irc_server_fill_hash);
        irssi_add_plains(irc_plains);

INCLUDE: IrcServer.xs
INCLUDE: IrcChannel.xs
INCLUDE: IrcQuery.xs
INCLUDE: Modes.xs
INCLUDE: Netsplit.xs

INCLUDE: Dcc.xs
INCLUDE: Flood.xs
INCLUDE: Notifylist.xs
