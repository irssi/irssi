#include "module.h"
#include "irssi-version.h"
#include "core.h"

#include "pidwait.h"
#include "session.h"

#define DEFAULT_COMMAND_CATEGORY "Perl scripts' commands"

void perl_signal_add_hash(int priority, SV *sv)
{
	HV *hv;
        HE *he;
	I32 len;

	if (!is_hvref(sv))
		croak("Usage: Irssi::signal_add(hash)");

        hv = hvref(sv);
	hv_iterinit(hv);
	while ((he = hv_iternext(hv)) != NULL)
                perl_signal_add_full(hv_iterkey(he, &len), HeVAL(he), priority);
}

static void perl_command_bind_add_hash(int priority, SV *sv, char *category)
{
	HV *hv;
        HE *he;
	I32 len;

        hv = hvref(sv);
	hv_iterinit(hv);
	while ((he = hv_iternext(hv)) != NULL)
		perl_command_bind_to(hv_iterkey(he, &len), category, HeVAL(he), priority);
}

static void handle_command_bind(int priority, int items, SV *p0, SV *p1, SV *p2)
{
	char *category;
	int hash;

	hash = items > 0 && is_hvref(p0);
	if (!hash) {
		if (items < 2 || items > 3)
			croak("Usage: Irssi::command_bind(signal, func, category)");
	} else if (items > 2)
		croak("Usage: Irssi::command_bind(signals_hash, category)");

	if (!hash) {
		category = items < 3 ? DEFAULT_COMMAND_CATEGORY :
			(char *)SvPV(p2, PL_na);
		perl_command_bind_to((char *)SvPV(p0, PL_na), category, p1, priority);
	} else {
		category = items < 2 ? DEFAULT_COMMAND_CATEGORY :
			(char *)SvPV(p1, PL_na);
		perl_command_bind_add_hash(priority, p0, category);
	}
}

MODULE = Irssi::Core  PACKAGE = Irssi
PROTOTYPES: ENABLE

void
signal_emit(signal, ...)
	char *signal
CODE:
	void *p[SIGNAL_MAX_ARGUMENTS];
	int n;

	memset(p, 0, sizeof(p));
	for (n = 1; n < items && n < SIGNAL_MAX_ARGUMENTS+1; n++) {
		if (SvPOKp(ST(n)))
			p[n-1] = SvPV(ST(n), PL_na);
		else if (irssi_is_ref_object(ST(n)))
			p[n-1] = irssi_ref_object(ST(n));
		else if (SvROK(ST(n)))
			p[n-1] = (void *) SvIV((SV*)SvRV(ST(n)));
		else if (SvIOK(ST(n)))
			p[n-1] = (void *)SvIV(ST(n));
		else
			p[n-1] = NULL;
	}
	signal_emit(signal, items-1, p[0], p[1], p[2], p[3], p[4], p[5]);

void
signal_continue(...)
CODE:
	void *p[SIGNAL_MAX_ARGUMENTS];
	int n;

	memset(p, 0, sizeof(p));
	for (n = 0; n < items && n < SIGNAL_MAX_ARGUMENTS; n++) {
		if (SvPOKp(ST(n)))
			p[n] = SvPV(ST(n), PL_na);
		else if (irssi_is_ref_object(ST(n)))
			p[n] = irssi_ref_object(ST(n));
		else if (SvROK(ST(n)))
			p[n] = (void *) SvIV((SV*)SvRV(ST(n)));
		else if (SvIOK(ST(n)))
			p[n] = (void *) SvIV(ST(n));
		else
			p[n] = NULL;
	}
	signal_continue(items, p[0], p[1], p[2], p[3], p[4], p[5]);

void
signal_add(...)
CODE:
	if (items != 1 && items != 2)
		croak("Usage: Irssi::signal_add(signal, func)");
	if (items == 2)
		perl_signal_add_full((char *)SvPV(ST(0),PL_na), ST(1),
				     SIGNAL_PRIORITY_DEFAULT);
	else
		perl_signal_add_hash(SIGNAL_PRIORITY_DEFAULT, ST(0));

void
signal_add_first(...)
CODE:
	if (items != 1 && items != 2)
		croak("Usage: Irssi::signal_add_first(signal, func)");
	if (items == 2)
		perl_signal_add_full((char *)SvPV(ST(0),PL_na), ST(1),
				     SIGNAL_PRIORITY_HIGH);
	else
		perl_signal_add_hash(SIGNAL_PRIORITY_HIGH, ST(0));

void
signal_add_last(...)
CODE:
	if (items != 1 && items != 2)
		croak("Usage: Irssi::signal_add_last(signal, func)");
	if (items == 2)
		perl_signal_add_full((char *)SvPV(ST(0),PL_na), ST(1),
				     SIGNAL_PRIORITY_LOW);
	else
		perl_signal_add_hash(SIGNAL_PRIORITY_LOW, ST(0));

void
signal_add_priority(...)
CODE:
	if (items != 2 && items != 3)
		croak("Usage: Irssi::signal_add_priority(signal, func, priority)");
	if (items == 3)
		perl_signal_add_full((char *)SvPV(ST(0),PL_na), ST(1), SvIV(ST(2)));
	else
		perl_signal_add_hash(SvIV(ST(0)), ST(1));

void
signal_register(...)
PREINIT:
	HV *hv;
        HE *he;
	I32 len, pos;
	const char *arr[7];
CODE:
	if (items != 1 || !is_hvref(ST(0)))
		croak("Usage: Irssi::signal_register(hash)");

        hv = hvref(ST(0));
	hv_iterinit(hv);
	while ((he = hv_iternext(hv)) != NULL) {
		const char *key = hv_iterkey(he, &len);
		SV *val = HeVAL(he);
		AV *av;

		if (!SvROK(val) || SvTYPE(SvRV(val)) != SVt_PVAV)
			croak("not array reference");

		av = (AV *) SvRV(val);
		len = av_len(av)+1;
		if (len > 6) len = 6;
		for (pos = 0; pos < len; pos++) {
                	SV **val = av_fetch(av, pos, 0);
			arr[pos] = SvPV(*val, PL_na);
		}
		arr[pos] = NULL;
		perl_signal_register(key, arr);
	}


int
SIGNAL_PRIORITY_LOW()
CODE:
	RETVAL = SIGNAL_PRIORITY_LOW;
OUTPUT:
	RETVAL

int
SIGNAL_PRIORITY_DEFAULT()
CODE:
	RETVAL = SIGNAL_PRIORITY_DEFAULT;
OUTPUT:
	RETVAL

int
SIGNAL_PRIORITY_HIGH()
CODE:
	RETVAL = SIGNAL_PRIORITY_HIGH;
OUTPUT:
	RETVAL

void
signal_remove(signal, func)
	char *signal
	SV *func
CODE:
	perl_signal_remove(signal, func);

void
signal_stop()

void
signal_stop_by_name(signal)
	char *signal

char *
signal_get_emitted()
CODE:
	RETVAL = (char *) signal_get_emitted();
OUTPUT:
	RETVAL

int
signal_get_emitted_id()

int
timeout_add(msecs, func, data)
	int msecs
	SV *func
	SV *data
CODE:
	if (msecs < 10) {
		croak("Irssi::timeout() : msecs must be >= 10");
		RETVAL = -1;
	} else {
		RETVAL = perl_timeout_add(msecs, func, data, FALSE);
	}
OUTPUT:
	RETVAL

int
timeout_add_once(msecs, func, data)
	int msecs
	SV *func
	SV *data
CODE:
	if (msecs < 10) {
		croak("Irssi::timeout_once() : msecs must be >= 10");
		RETVAL = -1;
	} else {
		RETVAL = perl_timeout_add(msecs, func, data, TRUE);
	}
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
	SV *func
	SV *data
CODE:
	RETVAL = perl_input_add(source, condition, func, data, FALSE);
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

void
bits2level(bits)
	int bits
PREINIT:
	char *ret;
PPCODE:
	ret = bits2level(bits);
	XPUSHs(sv_2mortal(new_pv(ret)));
	g_free(ret);

int
combine_level(level, str)
	int level
	char *str

void
command(cmd)
	char *cmd
CODE:
	perl_command(cmd, NULL, NULL);

void
commands()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(plain_bless(tmp->data, "Irssi::Command")));
	}

void
command_bind_first(...)
CODE:
	handle_command_bind(SIGNAL_PRIORITY_HIGH, items, ST(0), ST(1), ST(2));

void
command_bind(...)
CODE:
	handle_command_bind(SIGNAL_PRIORITY_DEFAULT, items, ST(0), ST(1), ST(2));

void
command_bind_last(...)
CODE:
	handle_command_bind(SIGNAL_PRIORITY_LOW, items, ST(0), ST(1), ST(2));

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
	SV *func
CODE:
	perl_command_unbind(cmd, func);

void
command_set_options(cmd, options)
	char *cmd
	char *options

void
pidwait_add(pid)
	int pid

void 
pidwait_remove(pid)
	int pid

void
parse_special(cmd, data="", flags=0)
	char *cmd
	char *data
	int flags
PREINIT:
	char *ret;
PPCODE:
	ret = parse_special_string(cmd, NULL, NULL, data, NULL, flags);
	XPUSHs(sv_2mortal(new_pv(ret)));
	g_free_not_null(ret);

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
get_irssi_binary()
CODE:
	RETVAL = irssi_binary;
OUTPUT:
	RETVAL

char *
version()
PREINIT:
	char version[100];
CODE:
	g_snprintf(version, sizeof(version), "%d.%04d",
		   IRSSI_VERSION_DATE, IRSSI_VERSION_TIME);
	RETVAL = version;
OUTPUT:
        RETVAL

int
get_gui()
CODE:
	RETVAL = irssi_gui;
OUTPUT:
	RETVAL

int
IRSSI_GUI_NONE()
CODE:
	RETVAL = IRSSI_GUI_NONE;
OUTPUT:
	RETVAL

int
IRSSI_GUI_TEXT()
CODE:
	RETVAL = IRSSI_GUI_TEXT;
OUTPUT:
	RETVAL

int
IRSSI_GUI_GTK()
CODE:
	RETVAL = IRSSI_GUI_GTK;
OUTPUT:
	RETVAL

int
IRSSI_GUI_GNOME()
CODE:
	RETVAL = IRSSI_GUI_GNOME;
OUTPUT:
	RETVAL

int
IRSSI_GUI_QT()
CODE:
	RETVAL = IRSSI_GUI_QT;
OUTPUT:
	RETVAL

int
IRSSI_GUI_KDE()
CODE:
	RETVAL = IRSSI_GUI_KDE;
OUTPUT:
	RETVAL

#*******************************
MODULE = Irssi::Core	PACKAGE = Irssi::Server
#*******************************

void
parse_special(server, cmd, data="", flags=0)
	Irssi::Server server
	char *cmd
	char *data
	int flags
PREINIT:
	char *ret;
PPCODE:
	ret = parse_special_string(cmd, server, NULL, data, NULL, flags);
	XPUSHs(sv_2mortal(new_pv(ret)));
	g_free_not_null(ret);

void
command(server, cmd)
	Irssi::Server server
	char *cmd
CODE:
	perl_command(cmd, server, NULL);


#*******************************
MODULE = Irssi::Core	PACKAGE = Irssi::Windowitem
#*******************************

void
parse_special(item, cmd, data="", flags=0)
	Irssi::Windowitem item
	char *cmd
	char *data
	int flags
PREINIT:
	char *ret;
PPCODE:
	ret = parse_special_string(cmd, item->server, item, data, NULL, flags);
	XPUSHs(sv_2mortal(new_pv(ret)));
	g_free_not_null(ret);

void
command(item, cmd)
	Irssi::Windowitem item
	char *cmd
CODE:
	perl_command(cmd, item->server, item);

