MODULE = Irssi  PACKAGE = Irssi

void
signal_emit(signal, ...)
	char *signal
PREINIT:
        STRLEN n_a;
CODE:
	void *p[6];
	int n;

	memset(p, 0, sizeof(p));
	for (n = 1; n < items && n < 6; n++) {
		p[n-1] = SvPOKp(ST(n)) ? SvPV(ST(n), n_a) : (void *) SvIV((SV*)SvRV(ST(n)));
	}
	signal_emit(signal, items-1, p[0], p[1], p[2], p[3], p[4], p[5]);

void
signal_add(signal, func)
	char *signal
	char *func
CODE:
	perl_signal_add(signal, func);

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
	char *data
CODE:
	RETVAL = perl_timeout_add(msecs, func, data);
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
	char *data
CODE:
	RETVAL = perl_input_add(source, condition, func, data);
OUTPUT:
	RETVAL

void
input_remove(tag)
	int tag
CODE:
	perl_source_remove(tag);

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
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Command", 0);
	for (tmp = commands; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(tmp->data))), stash)));
	}

void
command_bind(cmd, category, func)
	char *cmd
	char *category
	char *func
CODE:
	char *signal;

	if (*category == '\0') category = "Perl scripts' commands";
	command_bind(cmd, category, NULL);
	signal = g_strconcat("command ", cmd, NULL);
	perl_signal_add(signal, func);
	g_free(signal);

void
command_unbind(cmd, func)
	char *cmd
	char *func
CODE:
	char *signal;

	signal = g_strconcat("command ", cmd, NULL);
	perl_signal_remove(signal, func);
	g_free(signal);

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Command  PREFIX = command_
#*******************************

void
values(cmd)
	Irssi::Command cmd
PREINIT:
        HV *hv;
PPCODE:
	hv = newHV();
	hv_store(hv, "category", 8, new_pv(cmd->category), 0);
	hv_store(hv, "cmd", 3, new_pv(cmd->cmd), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));
