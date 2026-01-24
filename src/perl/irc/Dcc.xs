#define PERL_NO_GET_CONTEXT
#include "module.h"

static int initialized = FALSE;

static void perl_dcc_fill_hash(HV *hv, DCC_REC *dcc)
{
	(void) hv_store(hv, "type", 4, new_pv(dcc_type2str(dcc->type)), 0);
	(void) hv_store(hv, "orig_type", 9, new_pv(dcc_type2str(dcc->orig_type)), 0);
	(void) hv_store(hv, "created", 7, newSViv(dcc->created), 0);

	(void) hv_store(hv, "server", 6, iobject_bless(dcc->server), 0);
	(void) hv_store(hv, "servertag", 9, new_pv(dcc->servertag), 0);
	(void) hv_store(hv, "mynick", 6, new_pv(dcc->mynick), 0);
	(void) hv_store(hv, "nick", 4, new_pv(dcc->nick), 0);

	(void) hv_store(hv, "chat", 4, simple_iobject_bless(dcc->chat), 0);
	(void) hv_store(hv, "target", 6, new_pv(dcc->target), 0);
	(void) hv_store(hv, "arg", 3, new_pv(dcc->arg), 0);

	(void) hv_store(hv, "addr", 4, new_pv(dcc->addrstr), 0);
	(void) hv_store(hv, "port", 4, newSViv(dcc->port), 0);

	(void) hv_store(hv, "starttime", 9, newSViv(dcc->starttime), 0);
	(void) hv_store(hv, "transfd", 7, newSViv(dcc->transfd), 0);
}

static void perl_dcc_chat_fill_hash(HV *hv, CHAT_DCC_REC *dcc)
{
	perl_dcc_fill_hash(hv, (DCC_REC *) dcc);

	(void) hv_store(hv, "id", 2, new_pv(dcc->id), 0);
	(void) hv_store(hv, "mirc_ctcp", 9, newSViv(dcc->mirc_ctcp), 0);
	(void) hv_store(hv, "connection_lost", 15, newSViv(dcc->connection_lost), 0);
}

static void perl_dcc_file_fill_hash(HV *hv, FILE_DCC_REC *dcc)
{
	perl_dcc_fill_hash(hv, (DCC_REC *) dcc);

	(void) hv_store(hv, "size", 4, newSViv(dcc->size), 0);
	(void) hv_store(hv, "skipped", 7, newSViv(dcc->skipped), 0);
}

static void perl_dcc_get_fill_hash(HV *hv, GET_DCC_REC *dcc)
{
	perl_dcc_file_fill_hash(hv, (FILE_DCC_REC *) dcc);

	(void) hv_store(hv, "get_type", 8, newSViv(dcc->get_type), 0);
	(void) hv_store(hv, "file", 4, new_pv(dcc->file), 0);
	(void) hv_store(hv, "file_quoted", 11, newSViv(dcc->file_quoted), 0);
}

static void perl_dcc_send_fill_hash(HV *hv, SEND_DCC_REC *dcc)
{
	perl_dcc_file_fill_hash(hv, (FILE_DCC_REC *) dcc);

	(void) hv_store(hv, "file_quoted", 11, newSViv(dcc->file_quoted), 0);
	(void) hv_store(hv, "waitforend", 10, newSViv(dcc->waitforend), 0);
	(void) hv_store(hv, "gotalldata", 10, newSViv(dcc->gotalldata), 0);
}

static PLAIN_OBJECT_INIT_REC irc_dcc_plains[] = { { "Irssi::Irc::Dcc",
	                                            (PERL_OBJECT_FUNC) perl_dcc_fill_hash },

	                                          { NULL, NULL } };

/********************************/

MODULE = Irssi::Irc::Dcc  PACKAGE = Irssi::Irc

PROTOTYPES: ENABLE

void
dccs()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) 
		XPUSHs(sv_2mortal(simple_iobject_bless((DCC_REC *) tmp->data)));

void
dcc_register_type(type)
	char *type

void
dcc_unregister_type(type)
	char *type

int
dcc_str2type(str)
	char *str

char *
dcc_type2str(type)
	int type
CODE:
	RETVAL = (char *) module_find_id_str("DCC", type);
OUTPUT:
	RETVAL

Irssi::Irc::Dcc
dcc_find_request_latest(type)
	int type

Irssi::Irc::Dcc
dcc_find_request(type, nick, arg)
	int type
	char *nick
	char *arg

Irssi::Irc::Dcc::Chat
dcc_chat_find_id(id)
	char *id

void
dcc_chat_send(dcc, data)
	Irssi::Irc::Dcc::Chat dcc
	char *data

void
dcc_ctcp_message(server, target, chat, notice, msg)
	Irssi::Irc::Server server
	char *target
	Irssi::Irc::Dcc::Chat chat
	int notice
	char *msg

void
dcc_get_download_path(fname)
	char *fname
PREINIT:
	char *ret;
PPCODE:
	ret = dcc_get_download_path(fname);
	XPUSHs(sv_2mortal(new_pv(ret)));
	g_free(ret);

#*******************************
MODULE = Irssi::Irc::Dcc  PACKAGE = Irssi::Irc::Dcc  PREFIX = dcc_
#*******************************

void
dcc_init_rec(dcc, server, chat, nick, arg)
	Irssi::Irc::Dcc dcc
	Irssi::Irc::Server server
	Irssi::Irc::Dcc::Chat chat
	char *nick
	char *arg

void
dcc_destroy(dcc)
	Irssi::Irc::Dcc dcc

void
dcc_close(dcc)
	Irssi::Irc::Dcc dcc

void
dcc_reject(dcc, server)
	Irssi::Irc::Dcc dcc
	Irssi::Irc::Server server

#*******************************
MODULE = Irssi::Irc::Dcc  PACKAGE = Irssi::Windowitem  PREFIX = item_
#*******************************

Irssi::Irc::Dcc::Chat
item_get_dcc(item)
	Irssi::Windowitem item

#*******************************
MODULE = Irssi::Irc::Dcc  PACKAGE = Irssi::Irc::Dcc
#*******************************

void
init()
CODE:
	if (initialized)
		return;
	perl_api_version_check("Irssi::Irc::Dcc");
	initialized = TRUE;

	irssi_add_object(module_get_uniq_id_str("DCC", "CHAT"), 0, "Irssi::Irc::Dcc::Chat",
	                 (PERL_OBJECT_FUNC) perl_dcc_chat_fill_hash);
	irssi_add_object(module_get_uniq_id_str("DCC", "GET"), 0, "Irssi::Irc::Dcc::Get",
	                 (PERL_OBJECT_FUNC) perl_dcc_get_fill_hash);
	irssi_add_object(module_get_uniq_id_str("DCC", "SEND"), 0, "Irssi::Irc::Dcc::Send",
	                 (PERL_OBJECT_FUNC) perl_dcc_send_fill_hash);
	irssi_add_object(module_get_uniq_id_str("DCC", "SERVER"), 0, "Irssi::Irc::Dcc::Server",
	                 (PERL_OBJECT_FUNC) perl_dcc_send_fill_hash);
	irssi_add_plains(irc_dcc_plains);
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
	/* nothing * /
