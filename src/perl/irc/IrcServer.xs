MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Server  PREFIX = irc_server_

char *
irc_server_get_channels(server)
	Irssi::Irc::Server server

void
send_raw(server, cmd)
	Irssi::Irc::Server server
	char *cmd
CODE:
	irc_send_cmd(server, cmd);

void
send_raw_now(server, cmd)
	Irssi::Irc::Server server
	char *cmd
CODE:
	irc_send_cmd_now(server, cmd);

void
send_raw_split(server, cmd, nickarg, max_nicks)
	Irssi::Irc::Server server
	char *cmd
	int nickarg
	int max_nicks
CODE:
	irc_send_cmd_split(server, cmd, nickarg, max_nicks);

void
init(server)
	Irssi::Irc::Server server
PREINIT:
	HV *hv;
CODE:
	hv = hvref(ST(0));
	if (hv != NULL) {
		perl_server_fill_hash(hv, server);

		hv_store(hv, "real_address", 12, new_pv(server->real_address), 0);
		hv_store(hv, "usermode", 8, new_pv(server->usermode), 0);
		hv_store(hv, "userhost", 8, new_pv(server->userhost), 0);
	}


MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Connect  PREFIX = irc_server_

Irssi::Irc::Server
irc_server_connect(conn)
	Irssi::Irc::Connect conn

void
init(conn)
	Irssi::Irc::Connect conn
PREINIT:
	HV *hv;
CODE:
	hv = hvref(ST(0));
	if (hv != NULL) {
		perl_connect_fill_hash(hv, conn);
		hv_store(hv, "alternate_nick", 14, new_pv(conn->alternate_nick), 0);
	}
