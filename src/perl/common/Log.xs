MODULE = Irssi  PACKAGE = Irssi

void
logs()
PREINIT:
	GSList *tmp;
	HV *stash;
PPCODE:
	stash = gv_stashpv("Irssi::Log", 0);
	for (tmp = logs; tmp != NULL; tmp = tmp->next) {
		push_bless(tmp->data, stash);
	}

Irssi::Log
log_create_rec(fname, level)
	char *fname
	int level

Irssi::Log
log_find(fname)
	char *fname

#*******************************
MODULE = Irssi  PACKAGE = Irssi::Log  PREFIX = log_
#*******************************

void
log_item_add(log, type, name, server)
	Irssi::Log log
	int type
	char *name
	Irssi::Server server

void
log_item_destroy(log, item)
	Irssi::Log log
	Irssi::Logitem item

Irssi::Logitem
log_item_find(log, type, item, server)
	Irssi::Log log
	int type
	char *item
	Irssi::Server server

void
log_update(log)
	Irssi::Log log

void
log_close(log)
	Irssi::Log log

void
log_write_rec(log, str)
	Irssi::Log log
	char *str

void
log_start_logging(log)
	Irssi::Log log

void
log_stop_logging(log)
	Irssi::Log log
