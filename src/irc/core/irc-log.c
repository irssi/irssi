static void sig_log(SERVER_REC *server, const char *channel, gpointer level, const char *str)
{
    gint loglevel;

    g_return_if_fail(str != NULL);

    loglevel = GPOINTER_TO_INT(level);
    if (loglevel == MSGLEVEL_NEVER || logs == NULL) return;

    /* Check if line should be saved in logs */
    log_file_write(server, channel, loglevel, str);
}


static void event_away(const char *data, IRC_SERVER_REC *server)
{
	LOG_REC *log;
	const char *fname, *level;

	fname = settings_get_str("awaylog_file");
	level = settings_get_str("awaylog_level");
	if (*fname == '\0' || *level == '\0') return;

	log = log_file_find(fname);
	if (log != NULL) {
		/* awaylog already created */
		if (log->handle == -1) {
			/* ..but not open, open it. */
			log_file_open(log);
		}
		return;
	}

	log = log_create(fname, level);
	if (log != NULL) log_file_open(log);
}

static void event_unaway(const char *data, IRC_SERVER_REC *server)
{
	LOG_REC *rec;
	const char *fname;

	fname = settings_get_str("awaylog_file");
	if (*fname == '\0') return;

	rec = log_file_find(fname);
	if (rec == NULL || rec->handle == -1) {
		/* awaylog not open */
		return;
	}

	log_file_destroy(rec);
}

void log_init(void)
{
	settings_add_str("misc", "awaylog_file", "~/.irssi/away.log");
	settings_add_str("misc", "awaylog_level", "-all +msgs +hilight");

	signal_add("print text stripped", (SIGNAL_FUNC) sig_log);
	signal_add("event 306", (SIGNAL_FUNC) event_away);
	signal_add("event 305", (SIGNAL_FUNC) event_unaway);
}

void log_deinit(void)
{
	signal_remove("print text stripped", (SIGNAL_FUNC) sig_log);
	signal_remove("event 306", (SIGNAL_FUNC) event_away);
	signal_remove("event 305", (SIGNAL_FUNC) event_unaway);
}
