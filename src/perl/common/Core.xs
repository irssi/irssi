#include "module.h"
#include "irssi-version.h"

MODULE = Irssi::Core  PACKAGE = Irssi
PROTOTYPES: ENABLE

void
signal_emit(signal, ...)
	char *signal
PREINIT:
        STRLEN n_a;
CODE:
	void *p[SIGNAL_MAX_ARGUMENTS];
	int n;

	memset(p, 0, sizeof(p));
	for (n = 1; n < items && n < SIGNAL_MAX_ARGUMENTS+1; n++) {
		if (SvPOKp(ST(n)))
			p[n-1] = SvPV(ST(n), n_a);
		else if (irssi_is_ref_object(ST(n)))
			p[n-1] = irssi_ref_object(ST(n));
		else
			p[n-1] = (void *) SvIV((SV*)SvRV(ST(n)));
	}
	signal_emit(signal, items-1, p[0], p[1], p[2], p[3], p[4], p[5]);

void
signal_add(signal, func)
	char *signal
	char *func
CODE:
	perl_signal_add(signal, func);

void
signal_add_first(signal, func)
	char *signal
	char *func
CODE:
	perl_signal_add_first(signal, func);

void
signal_add_last(signal, func)
	char *signal
	char *func
CODE:
	perl_signal_add_last(signal, func);

void
signal_remove(signal, func)
	char *signal
	char *func
CODE:
	perl_signal_remove(signal, func);

void
signal_stop()

void
signal_stop_by_name(signal)
	char *signal

int
timeout_add(msecs, func, data)
	int msecs
	char *func
	void *data
CODE:
	RETVAL = perl_timeout_add(msecs, func, ST(2));
OUTPUT:
	RETVAL

void
timeout_remove(tag)
	int tag
CODE:
	perl_source_remove(tag);


int
INPUT_READ()
CODE:
	RETVAL = G_INPUT_READ;
OUTPUT:
	RETVAL

int
INPUT_WRITE()
CODE:
	RETVAL = G_INPUT_WRITE;
OUTPUT:
	RETVAL

int
input_add(source, condition, func, data)
	int source
	int condition
	char *func
	void *data
CODE:
	RETVAL = perl_input_add(source, condition, func, ST(2));
OUTPUT:
	RETVAL

void
input_remove(tag)
	int tag
CODE:
	perl_source_remove(tag);

# maybe there's some easier way than this..? :)
int
MSGLEVEL_CRAP()
CODE:
	RETVAL = MSGLEVEL_CRAP;
OUTPUT:
	RETVAL

int
MSGLEVEL_MSGS()
CODE:
	RETVAL = MSGLEVEL_MSGS;
OUTPUT:
	RETVAL

int
MSGLEVEL_PUBLIC()
CODE:
	RETVAL = MSGLEVEL_PUBLIC;
OUTPUT:
	RETVAL

int
MSGLEVEL_NOTICES()
CODE:
	RETVAL = MSGLEVEL_NOTICES;
OUTPUT:
	RETVAL

int
MSGLEVEL_SNOTES()
CODE:
	RETVAL = MSGLEVEL_SNOTES;
OUTPUT:
	RETVAL

int
MSGLEVEL_CTCPS()
CODE:
	RETVAL = MSGLEVEL_CTCPS;
OUTPUT:
	RETVAL

int
MSGLEVEL_ACTIONS()
CODE:
	RETVAL = MSGLEVEL_ACTIONS;
OUTPUT:
	RETVAL

int
MSGLEVEL_JOINS()
CODE:
	RETVAL = MSGLEVEL_JOINS;
OUTPUT:
	RETVAL

int
MSGLEVEL_PARTS()
CODE:
	RETVAL = MSGLEVEL_PARTS;
OUTPUT:
	RETVAL

int
MSGLEVEL_QUITS()
CODE:
	RETVAL = MSGLEVEL_QUITS;
OUTPUT:
	RETVAL

int
MSGLEVEL_KICKS()
CODE:
	RETVAL = MSGLEVEL_KICKS;
OUTPUT:
	RETVAL

int
MSGLEVEL_MODES()
CODE:
	RETVAL = MSGLEVEL_MODES;
OUTPUT:
	RETVAL

int
MSGLEVEL_TOPICS()
CODE:
	RETVAL = MSGLEVEL_TOPICS;
OUTPUT:
	RETVAL

int
MSGLEVEL_WALLOPS()
CODE:
	RETVAL = MSGLEVEL_WALLOPS;
OUTPUT:
	RETVAL

int
MSGLEVEL_INVITES()
CODE:
	RETVAL = MSGLEVEL_INVITES;
OUTPUT:
	RETVAL

int
MSGLEVEL_NICKS()
CODE:
	RETVAL = MSGLEVEL_NICKS;
OUTPUT:
	RETVAL

int
MSGLEVEL_DCC()
CODE:
	RETVAL = MSGLEVEL_DCC;
OUTPUT:
	RETVAL

int
MSGLEVEL_DCCMSGS()
CODE:
	RETVAL = MSGLEVEL_DCCMSGS;
OUTPUT:
	RETVAL

int
MSGLEVEL_CLIENTNOTICE()
CODE:
	RETVAL = MSGLEVEL_CLIENTNOTICE;
OUTPUT:
	RETVAL

int
MSGLEVEL_CLIENTCRAP()
CODE:
	RETVAL = MSGLEVEL_CLIENTCRAP;
OUTPUT:
	RETVAL

int
MSGLEVEL_CLIENTERROR()
CODE:
	RETVAL = MSGLEVEL_CLIENTERROR;
OUTPUT:
	RETVAL

int
MSGLEVEL_HILIGHT()
CODE:
	RETVAL = MSGLEVEL_HILIGHT;
OUTPUT:
	RETVAL

int
MSGLEVEL_ALL()
CODE:
	RETVAL = MSGLEVEL_ALL;
OUTPUT:
	RETVAL

int
MSGLEVEL_NOHILIGHT()
CODE:
	RETVAL = MSGLEVEL_NOHILIGHT;
OUTPUT:
	RETVAL

int
MSGLEVEL_NO_ACT()
CODE:
	RETVAL = MSGLEVEL_NO_ACT;
OUTPUT:
	RETVAL

int
MSGLEVEL_NEVER()
CODE:
	RETVAL = MSGLEVEL_NEVER;
OUTPUT:
	RETVAL

int
MSGLEVEL_LASTLOG()
CODE:
	RETVAL = MSGLEVEL_LASTLOG;
OUTPUT:
	RETVAL

int
level2bits(str)
	char *str

char *
bits2level(bits)
	int bits

int
combine_level(level, str)
	int level
	char *str

void
commands()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(plain_bless(tmp->data, "Irssi::Command")));
	}

void
command_bind_first(cmd, func, category = "Perl scripts' commands")
	char *cmd
	char *category
	char *func
CODE:
	perl_command_bind_first(cmd, category, func);

void
command_bind(cmd, func, category = "Perl scripts' commands")
	char *cmd
	char *category
	char *func
CODE:
	perl_command_bind(cmd, category, func);

void
command_bind_last(cmd, func, category = "Perl scripts' commands")
	char *cmd
	char *category
	char *func
CODE:
	perl_command_bind_last(cmd, category, func);

void
command_runsub(cmd, data, server, item)
	char *cmd
	char *data
	Irssi::Server server
	Irssi::Windowitem item
CODE:
	perl_command_runsub(cmd, data, server, item);

void
command_unbind(cmd, func)
	char *cmd
	char *func
CODE:
	perl_command_unbind(cmd, func);

void
pidwait_add(pid)
	int pid

void 
pidwait_remove(pid)
	int pid

char *
parse_special(cmd, data="", flags=0)
	char *cmd
	char *data
	int flags
CODE:
	RETVAL = parse_special_string(cmd, NULL, NULL, data, NULL, flags);
OUTPUT:
	RETVAL

char *
get_irssi_dir()
CODE:
	RETVAL = (char *) get_irssi_dir();
OUTPUT:
	RETVAL

char *
get_irssi_config()
CODE:
	RETVAL = (char *) get_irssi_config();
OUTPUT:
	RETVAL

char *
version()
CODE:
	RETVAL = IRSSI_VERSION_DATE;
OUTPUT:
	RETVAL

#*******************************
MODULE = Irssi::Core	PACKAGE = Irssi::Server
#*******************************

char *
parse_special(server, cmd, data="", flags=0)
	Irssi::Server server
	char *cmd
	char *data
	int flags
CODE:
	RETVAL = parse_special_string(cmd, server, NULL, data, NULL, flags);
OUTPUT:
	RETVAL

#*******************************
MODULE = Irssi::Core	PACKAGE = Irssi::Windowitem
#*******************************

char *
parse_special(item, cmd, data="", flags=0)
	Irssi::Windowitem item
	char *cmd
	char *data
	int flags
CODE:
	RETVAL = parse_special_string(cmd, item->server, item, data, NULL, flags);
OUTPUT:
	RETVAL
