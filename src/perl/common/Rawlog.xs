#include "module.h"

MODULE = Irssi::Rawlog  PACKAGE = Irssi
PROTOTYPES: ENABLE

void
rawlog_set_size(lines)
	int lines

Irssi::Rawlog
rawlog_create()

#*******************************
MODULE = Irssi::Rawlog  PACKAGE = Irssi::Rawlog  PREFIX = rawlog_
#*******************************

void
rawlog_get_lines(rawlog)
	Irssi::Rawlog rawlog
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = rawlog->lines; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(new_pv(tmp->data)));
	}

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
