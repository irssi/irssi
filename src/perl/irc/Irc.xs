#include "module.h"

static int initialized = FALSE;

static void perl_irc_connect_fill_hash(HV *hv, IRC_SERVER_CONNECT_REC *conn)
{
	perl_connect_fill_hash(hv, (SERVER_CONNECT_REC *) conn);
	hv_store(hv, "alternate_nick", 14, new_pv(conn->alternate_nick), 0);
}

static void perl_irc_server_fill_hash(HV *hv, IRC_SERVER_REC *server)
{
       	perl_server_fill_hash(hv, (SERVER_REC *) server);

       	hv_store(hv, "real_address", 12, new_pv(server->real_address), 0);
       	hv_store(hv, "usermode", 8, new_pv(server->usermode), 0);
       	hv_store(hv, "userhost", 8, new_pv(server->userhost), 0);

	hv_store(hv, "max_cmds_at_once", 16, newSViv(server->max_cmds_at_once), 0);
	hv_store(hv, "cmd_queue_speed", 15, newSViv(server->cmd_queue_speed), 0);
	hv_store(hv, "max_query_chans", 15, newSViv(server->max_query_chans), 0);

	hv_store(hv, "max_kicks_in_cmd", 16, newSViv(server->max_kicks_in_cmd), 0);
	hv_store(hv, "max_msgs_in_cmd", 15, newSViv(server->max_msgs_in_cmd), 0);
	hv_store(hv, "max_modes_in_cmd", 16, newSViv(server->max_modes_in_cmd), 0);
	hv_store(hv, "max_whois_in_cmd", 16, newSViv(server->max_whois_in_cmd), 0);
	hv_store(hv, "isupport_sent", 13, newSViv(server->isupport_sent), 0);
}

static void perl_ban_fill_hash(HV *hv, BAN_REC *ban)
{
	hv_store(hv, "ban", 3, new_pv(ban->ban), 0);
	hv_store(hv, "setby", 5, new_pv(ban->setby), 0);
	hv_store(hv, "time", 4, newSViv(ban->time), 0);
}

static void perl_dcc_fill_hash(HV *hv, DCC_REC *dcc)
{
	hv_store(hv, "type", 4, new_pv(dcc_type2str(dcc->type)), 0);
	hv_store(hv, "orig_type", 9, new_pv(dcc_type2str(dcc->orig_type)), 0);
	hv_store(hv, "created", 7, newSViv(dcc->created), 0);

	hv_store(hv, "server", 6, iobject_bless(dcc->server), 0);
	hv_store(hv, "servertag", 9, new_pv(dcc->servertag), 0);
	hv_store(hv, "mynick", 6, new_pv(dcc->mynick), 0);
	hv_store(hv, "nick", 4, new_pv(dcc->nick), 0);

	hv_store(hv, "chat", 4, simple_iobject_bless(dcc->chat), 0);
	hv_store(hv, "target", 6, new_pv(dcc->target), 0);
	hv_store(hv, "arg", 3, new_pv(dcc->arg), 0);

	hv_store(hv, "addr", 4, new_pv(dcc->addrstr), 0);
	hv_store(hv, "port", 4, newSViv(dcc->port), 0);

	hv_store(hv, "starttime", 9, newSViv(dcc->starttime), 0);
	hv_store(hv, "transfd", 7, newSViv(dcc->transfd), 0);
}

static void perl_dcc_chat_fill_hash(HV *hv, CHAT_DCC_REC *dcc)
{
        perl_dcc_fill_hash(hv, (DCC_REC *) dcc);

	hv_store(hv, "id", 2, new_pv(dcc->id), 0);
	hv_store(hv, "mirc_ctcp", 9, newSViv(dcc->mirc_ctcp), 0);
	hv_store(hv, "connection_lost", 15, newSViv(dcc->connection_lost), 0);
}

static void perl_dcc_file_fill_hash(HV *hv, FILE_DCC_REC *dcc)
{
        perl_dcc_fill_hash(hv, (DCC_REC *) dcc);

	hv_store(hv, "size", 4, newSViv(dcc->size), 0);
	hv_store(hv, "skipped", 7, newSViv(dcc->skipped), 0);
}

static void perl_dcc_get_fill_hash(HV *hv, GET_DCC_REC *dcc)
{
        perl_dcc_file_fill_hash(hv, (FILE_DCC_REC *) dcc);

	hv_store(hv, "get_type", 8, newSViv(dcc->get_type), 0);
	hv_store(hv, "file", 4, new_pv(dcc->file), 0);
	hv_store(hv, "file_quoted", 11, newSViv(dcc->file_quoted), 0);
}

static void perl_dcc_send_fill_hash(HV *hv, SEND_DCC_REC *dcc)
{
        perl_dcc_file_fill_hash(hv, (FILE_DCC_REC *) dcc);

	hv_store(hv, "file_quoted", 11, newSViv(dcc->file_quoted), 0);
	hv_store(hv, "waitforend", 10, newSViv(dcc->waitforend), 0);
	hv_store(hv, "gotalldata", 10, newSViv(dcc->gotalldata), 0);
}

static void perl_netsplit_fill_hash(HV *hv, NETSPLIT_REC *netsplit)
{
        AV *av;
        GSList *tmp;

	hv_store(hv, "nick", 4, new_pv(netsplit->nick), 0);
	hv_store(hv, "address", 7, new_pv(netsplit->address), 0);
	hv_store(hv, "destroy", 7, newSViv(netsplit->destroy), 0);

	hv_store(hv, "server", 6,
		 plain_bless(netsplit->server,
			     "Irssi::Irc::Netsplitserver"), 0);

	av = newAV();
	for (tmp = netsplit->channels; tmp != NULL; tmp = tmp->next) {
		av_push(av, plain_bless(tmp->data,
					"Irssi::Irc::Netsplitchannel"));
	}
	hv_store(hv, "channels", 8, newRV_noinc((SV*)av), 0);
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
	hv_store(hv, "op", 2, newSViv(rec->op), 0);
	hv_store(hv, "halfop", 6, newSViv(rec->halfop), 0);
	hv_store(hv, "voice", 5, newSViv(rec->voice), 0);
}

static void perl_notifylist_fill_hash(HV *hv, NOTIFYLIST_REC *notify)
{
	AV *av;
	char **tmp;

	hv_store(hv, "mask", 4, new_pv(notify->mask), 0);
	hv_store(hv, "away_check", 10, newSViv(notify->away_check), 0);

	av = newAV();
	if (notify->ircnets != NULL) {
		for (tmp = notify->ircnets; *tmp != NULL; tmp++) {
			av_push(av, new_pv(*tmp));
		}
	}
	hv_store(hv, "ircnets", 7, newRV_noinc((SV*)av), 0);
}

static void perl_client_fill_hash(HV *hv, CLIENT_REC *client)
{
	hv_store(hv, "nick", 4, new_pv(client->nick), 0);
	hv_store(hv, "host", 4, new_pv(client->host), 0);
	hv_store(hv, "proxy_address", 13, new_pv(client->proxy_address), 0);
	hv_store(hv, "server", 6, iobject_bless(client->server), 0);
	hv_store(hv, "pass_sent", 9, newSViv(client->pass_sent), 0);
	hv_store(hv, "user_sent", 9, newSViv(client->user_sent), 0);
	hv_store(hv, "connected", 9, newSViv(client->connected), 0);
	hv_store(hv, "want_ctcp", 9, newSViv(client->want_ctcp), 0);
	hv_store(hv, "ircnet", 6, new_pv(client->listen->ircnet), 0);
}

static PLAIN_OBJECT_INIT_REC irc_plains[] = {
	{ "Irssi::Irc::Ban", (PERL_OBJECT_FUNC) perl_ban_fill_hash },
	{ "Irssi::Irc::Dcc", (PERL_OBJECT_FUNC) perl_dcc_fill_hash },
	{ "Irssi::Irc::Netsplit", (PERL_OBJECT_FUNC) perl_netsplit_fill_hash },
	{ "Irssi::Irc::Netsplitserver", (PERL_OBJECT_FUNC) perl_netsplit_server_fill_hash },
	{ "Irssi::Irc::Netsplitchannel", (PERL_OBJECT_FUNC) perl_netsplit_channel_fill_hash },
	{ "Irssi::Irc::Notifylist", (PERL_OBJECT_FUNC) perl_notifylist_fill_hash },
	{ "Irssi::Irc::Client", (PERL_OBJECT_FUNC) perl_client_fill_hash },

	{ NULL, NULL }
};

MODULE = Irssi::Irc  PACKAGE = Irssi::Irc

PROTOTYPES: ENABLE

void
init()
PREINIT:
	int chat_type;
CODE:
	if (initialized) return;
	perl_api_version_check("Irssi::Irc");
	initialized = TRUE;

	chat_type = chat_protocol_lookup("IRC");

	irssi_add_object(module_get_uniq_id("SERVER CONNECT", 0),
			 chat_type, "Irssi::Irc::Connect",
			 (PERL_OBJECT_FUNC) perl_irc_connect_fill_hash);
	irssi_add_object(module_get_uniq_id("SERVER", 0),
			 chat_type, "Irssi::Irc::Server",
			 (PERL_OBJECT_FUNC) perl_irc_server_fill_hash);
	irssi_add_object(module_get_uniq_id_str("DCC", "CHAT"),
			 0, "Irssi::Irc::Dcc::Chat",
			 (PERL_OBJECT_FUNC) perl_dcc_chat_fill_hash);
	irssi_add_object(module_get_uniq_id_str("DCC", "GET"),
			 0, "Irssi::Irc::Dcc::Get",
			 (PERL_OBJECT_FUNC) perl_dcc_get_fill_hash);
	irssi_add_object(module_get_uniq_id_str("DCC", "SEND"),
			 0, "Irssi::Irc::Dcc::Send",
			 (PERL_OBJECT_FUNC) perl_dcc_send_fill_hash);
	irssi_add_object(module_get_uniq_id_str("DCC", "SERVER"),
			 0, "Irssi::Irc::Dcc::Server",
			 (PERL_OBJECT_FUNC) perl_dcc_send_fill_hash);
        irssi_add_plains(irc_plains);
	perl_eval_pv("@Irssi::Irc::Dcc::Chat::ISA = qw(Irssi::Irc::Dcc);\n"
		     "@Irssi::Irc::Dcc::Get::ISA = qw(Irssi::Irc::Dcc);\n"
		     "@Irssi::Irc::Dcc::Send::ISA = qw(Irssi::Irc::Dcc);\n"
		     "@Irssi::Irc::Dcc::Server::ISA = qw(Irssi::Irc::Dcc);\n",
		     TRUE);

void
deinit()
CODE:
	initialized = FALSE;

BOOT:
	irssi_boot(Irc__Channel);
	irssi_boot(Irc__Ctcp);
	irssi_boot(Irc__Dcc);
	irssi_boot(Irc__Modes);
	irssi_boot(Irc__Netsplit);
	irssi_boot(Irc__Notifylist);
	irssi_boot(Irc__Query);
	irssi_boot(Irc__Server);
	irssi_boot(Irc__Client);
