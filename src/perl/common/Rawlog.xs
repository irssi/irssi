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
