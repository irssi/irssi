#include "module.h"
#include "levels.h"

void connect_fill_hash(HV *hv, IRC_SERVER_CONNECT_REC *conn)
{
	hv_store(hv, "address", 7, new_pv(conn->address), 0);
	hv_store(hv, "port", 4, newSViv(conn->port), 0);
	hv_store(hv, "ircnet", 6, new_pv(conn->ircnet), 0);

	hv_store(hv, "password", 8, new_pv(conn->password), 0);
	hv_store(hv, "wanted_nick", 11, new_pv(conn->nick), 0);
	hv_store(hv, "alternate_nick", 14, new_pv(conn->alternate_nick), 0);
	hv_store(hv, "username", 8, new_pv(conn->username), 0);
	hv_store(hv, "realname", 8, new_pv(conn->realname), 0);
}

void server_fill_hash(HV *hv, IRC_SERVER_REC *server)
{
	HV *stash;

	connect_fill_hash(hv, server->connrec);
	hv_store(hv, "connect_time", 12, newSViv(server->connect_time), 0);

	hv_store(hv, "tag", 3, new_pv(server->tag), 0);
	hv_store(hv, "nick", 4, new_pv(server->nick), 0);

	hv_store(hv, "connected", 9, newSViv(server->connected), 0);
	hv_store(hv, "connection_lost", 15, newSViv(server->connection_lost), 0);

	stash = gv_stashpv("Irssi::Rawlog", 0);
	hv_store(hv, "rawlog", 6, sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(server->rawlog))), stash), 0);
}

MODULE = Irssi  PACKAGE = Irssi

PROTOTYPES: ENABLE

INCLUDE: Irssi-bans.xs
INCLUDE: Irssi-channel.xs
INCLUDE: Irssi-core.xs
INCLUDE: Irssi-dcc.xs
INCLUDE: Irssi-flood.xs
INCLUDE: Irssi-ignore.xs
INCLUDE: Irssi-log.xs
INCLUDE: Irssi-masks.xs
INCLUDE: Irssi-modes.xs
INCLUDE: Irssi-netsplit.xs
INCLUDE: Irssi-notifylist.xs
INCLUDE: Irssi-query.xs
INCLUDE: Irssi-rawlog.xs
INCLUDE: Irssi-server.xs
INCLUDE: Irssi-settings.xs
INCLUDE: Irssi-window.xs
