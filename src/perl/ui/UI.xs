#include "module.h"

static void perl_process_fill_hash(HV *hv, PROCESS_REC *process)
{
	hv_store(hv, "id", 2, newSViv(process->id), 0);
	hv_store(hv, "name", 4, new_pv(process->name), 0);
	hv_store(hv, "args", 4, new_pv(process->args), 0);

	hv_store(hv, "pid", 3, newSViv(process->pid), 0);
	hv_store(hv, "target", 6, new_pv(process->target), 0);
	if (process->target_win != NULL) {
		hv_store(hv, "target_win", 10,
			 plain_bless(process->target_win, "Irssi::UI::Window"), 0);
	}
	hv_store(hv, "shell", 5, newSViv(process->shell), 0);
	hv_store(hv, "notice", 6, newSViv(process->notice), 0);
	hv_store(hv, "silent", 6, newSViv(process->silent), 0);
}

static void perl_window_fill_hash(HV *hv, WINDOW_REC *window)
{
	hv_store(hv, "refnum", 6, newSViv(window->refnum), 0);
	hv_store(hv, "name", 4, new_pv(window->name), 0);

	if (window->active)
		hv_store(hv, "active", 6, irssi_bless(window->active), 0);
	if (window->active_server)
		hv_store(hv, "active_server", 13, irssi_bless(window->active_server), 0);

	hv_store(hv, "level", 5, newSViv(window->level), 0);
	hv_store(hv, "data_level", 8, newSViv(window->data_level), 0);
	hv_store(hv, "hilight_color", 10, new_pv(window->hilight_color), 0);
	hv_store(hv, "last_timestamp", 14, newSViv(window->last_timestamp), 0);
	hv_store(hv, "last_line", 9, newSViv(window->last_line), 0);
}

static void perl_text_dest_fill_hash(HV *hv, TEXT_DEST_REC *dest)
{
	hv_store(hv, "window", 6, plain_bless(dest->window, "Irssi::UI::Window"), 0);
	hv_store(hv, "server", 6, irssi_bless(dest->server), 0);
	hv_store(hv, "target", 6, new_pv(dest->target), 0);
	hv_store(hv, "level", 5, newSViv(dest->level), 0);

	hv_store(hv, "hilight_priority", 16, newSViv(dest->hilight_priority), 0);
	hv_store(hv, "hilight_color", 13, new_pv(dest->hilight_color), 0);
}

void printformat_perl(TEXT_DEST_REC *dest, char *format, char **arglist)
{
	THEME_REC *theme;
	char *module, *str;
	int formatnum;

	module = g_strdup(perl_get_package());
	theme = dest->window->theme == NULL ? current_theme :
		dest->window->theme;

	formatnum = format_find_tag(module, format);
	signal_emit("print format", 5, theme, module,
		    &dest, GINT_TO_POINTER(formatnum), arglist);

        str = format_get_text_theme_charargs(theme, module, dest, formatnum, arglist);
	if (*str != '\0') printtext_window(dest->window, dest->level, "%s", str);
	g_free(str);
	g_free(module);
}

static void perl_unregister_theme(const char *package)
{
	FORMAT_REC *formats;
	int n;

	formats = g_hash_table_lookup(default_formats, package);
	if (formats == NULL) return;

	for (n = 0; formats[n].def != NULL; n++) {
		g_free(formats[n].tag);
		g_free(formats[n].def);
	}
	g_free(formats);
	theme_unregister_module(package);
}

static void sig_script_destroy(const char *type, const char *name,
			       const char *package)
{
	if (strcmp(type, "PERL") == 0)
		perl_unregister_theme(package);
}

static void sig_perl_stop(void)
{
	GSList *tmp;
        char *package;

	/* themes */
	for (tmp = perl_scripts; tmp != NULL; tmp = tmp->next) {
		package = g_strdup_printf("Irssi::Script::%s",
					  (char *) tmp->data);
		perl_unregister_theme(package);
		g_free(package);
	}
}

static PLAIN_OBJECT_INIT_REC fe_plains[] = {
	{ "Irssi::UI::Process", (PERL_OBJECT_FUNC) perl_process_fill_hash },
	{ "Irssi::UI::Window", (PERL_OBJECT_FUNC) perl_window_fill_hash },
	{ "Irssi::UI::TextDest", (PERL_OBJECT_FUNC) perl_text_dest_fill_hash },

	{ NULL, NULL }
};

MODULE = Irssi::UI  PACKAGE = Irssi::UI

PROTOTYPES: ENABLE

void
init()
PREINIT:
	static int initialized = FALSE;
CODE:
	if (initialized) return;
	initialized = TRUE;

        irssi_add_plains(fe_plains);

	signal_add("script destroy", (SIGNAL_FUNC) sig_script_destroy);
	signal_add("perl stop", (SIGNAL_FUNC) sig_perl_stop);


INCLUDE: Themes.xs
INCLUDE: Window.xs
