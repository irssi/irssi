MODULE = Irssi  PACKAGE = Irssi

void
rawlog_set_size(lines)
	int lines

Irssi::Rawlog
rawlog_create()

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Server
#*******************************

void
rawlog_input(rawlog, str)
	Irssi::Rawlog rawlog
	char *str

void
rawlog_output(rawlog, str)
	Irssi::Rawlog rawlog
	char *str

void
rawlog_redirect(rawlog, str)
	Irssi::Rawlog rawlog
	char *str


#*******************************
MODULE = Irssi  PACKAGE = Irssi::Rawlog  PREFIX = rawlog_
#*******************************

void
values(rawlog)
	Irssi::Rawlog rawlog
PREINIT:
        HV *hv;
	AV *av;
	GSList *tmp;
PPCODE:
	hv = newHV();
	hv_store(hv, "logging", 7, newSViv(rawlog->logging), 0);
	hv_store(hv, "nlines", 6, newSViv(rawlog->nlines), 0);

	av = newAV();
	for (tmp = rawlog->lines; tmp != NULL; tmp = tmp->next) {
		av_push(av, new_pv(tmp->data));
	}
	hv_store(hv, "lines", 5, newRV_noinc((SV*)av), 0);
	XPUSHs(sv_2mortal(newRV_noinc((SV*)hv)));

void
rawlog_destroy(rawlog)
	Irssi::Rawlog rawlog

void
rawlog_input(rawlog, str)
	Irssi::Rawlog rawlog
	char *str

void
rawlog_output(rawlog, str)
	Irssi::Rawlog rawlog
	char *str

void
rawlog_redirect(rawlog, str)
	Irssi::Rawlog rawlog
	char *str

void
rawlog_open(rawlog, fname)
	Irssi::Rawlog rawlog
	char *fname

void
rawlog_close(rawlog)
	Irssi::Rawlog rawlog

void
rawlog_save(rawlog, fname)
	Irssi::Rawlog rawlog
	char *fname
