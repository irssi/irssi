MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Server  PREFIX = irc_server_

void
values(server)
	Irssi::Irc::Server server
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	perl_server_fill_hash(hv, (SERVER_REC *) server);

	hv_store(hv, "real_address", 12, new_pv(server->real_address), 0);
	hv_store(hv, "usermode", 8, new_pv(server->usermode), 0);
	hv_store(hv, "userhost", 8, new_pv(server->userhost), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

char *
irc_server_get_channels(server)
	Irssi::Irc::Server server

MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Connect  PREFIX = irc_server_

void
values(conn)
	Irssi::Irc::Connect conn
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	perl_server_connect_fill_hash(hv, (SERVER_CONNECT_REC *) conn);

	hv_store(hv, "alternate_nick", 14, new_pv(conn->alternate_nick), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

Irssi::Irc::Server
irc_server_connect(conn)
	Irssi::Irc::Connect conn
