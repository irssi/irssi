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
init(log)
	Irssi::Log log
PREINIT:
	HV *hv, *stash;
	AV *av;
	GSList *tmp;
CODE:
	hv = hvref(ST(0));
	if (hv != NULL) {
		hv_store(hv, "fname", 5, new_pv(log->fname), 0);
		hv_store(hv, "opened", 6, newSViv(log->opened), 0);
		hv_store(hv, "level", 5, newSViv(log->level), 0);
		hv_store(hv, "last", 4, newSViv(log->last), 0);
		hv_store(hv, "autoopen", 8, newSViv(log->autoopen), 0);
		hv_store(hv, "failed", 6, newSViv(log->failed), 0);
		hv_store(hv, "temp", 4, newSViv(log->temp), 0);

		stash = gv_stashpv("Irssi::LogItem", 0);
		av = newAV();
		for (tmp = log->items; tmp != NULL; tmp = tmp->next) {
			av_push(av, sv_2mortal(new_bless(tmp->data, stash)));
		}
		hv_store(hv, "items", 4, newRV_noinc((SV*)av), 0);
	}

void
log_item_add(log, type, name, server)
	Irssi::Log log
	int type
	char *name
	Irssi::Server server

void
log_item_destroy(log, item)
	Irssi::Log log
	Irssi::LogItem item

Irssi::LogItem
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

#*******************************
MODULE = Irssi  PACKAGE = Irssi::LogItem
#*******************************

void
init(item)
	Irssi::LogItem item
PREINIT:
	HV *hv;
CODE:
	hv = hvref(ST(0));
	if (hv != NULL) {
		hv_store(hv, "type", 4, newSViv(item->type), 0);
		hv_store(hv, "name", 4, new_pv(item->name), 0);
		hv_store(hv, "servertag", 9, new_pv(item->servertag), 0);
	}
