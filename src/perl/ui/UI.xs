#define PERL_NO_GET_CONTEXT
#include "module.h"

void perl_themes_init(void);
void perl_themes_deinit(void);

static int initialized = FALSE;

static void perl_process_fill_hash(HV *hv, PROCESS_REC *process)
{
	(void) hv_store(hv, "id", 2, newSViv(process->id), 0);
	(void) hv_store(hv, "name", 4, new_pv(process->name), 0);
	(void) hv_store(hv, "args", 4, new_pv(process->args), 0);

	(void) hv_store(hv, "pid", 3, newSViv(process->pid), 0);
	(void) hv_store(hv, "target", 6, new_pv(process->target), 0);
	if (process->target_win != NULL) {
		(void) hv_store(hv, "target_win", 10,
			 plain_bless(process->target_win, "Irssi::UI::Window"), 0);
	}
	(void) hv_store(hv, "shell", 5, newSViv(process->shell), 0);
	(void) hv_store(hv, "notice", 6, newSViv(process->notice), 0);
	(void) hv_store(hv, "silent", 6, newSViv(process->silent), 0);
}

static void perl_window_fill_hash(HV *hv, WINDOW_REC *window)
{
	(void) hv_store(hv, "refnum", 6, newSViv(window->refnum), 0);
	(void) hv_store(hv, "name", 4, new_pv(window->name), 0);
	(void) hv_store(hv, "history_name", 12, new_pv(window->history_name), 0);

	(void) hv_store(hv, "width", 5, newSViv(window->width), 0);
	(void) hv_store(hv, "height", 6, newSViv(window->height), 0);

	if (window->active)
		(void) hv_store(hv, "active", 6, iobject_bless(window->active), 0);
	if (window->active_server)
		(void) hv_store(hv, "active_server", 13, iobject_bless(window->active_server), 0);

	(void) hv_store(hv, "servertag", 9, new_pv(window->servertag), 0);
	(void) hv_store(hv, "level", 5, newSViv(window->level), 0);

	(void) hv_store(hv, "immortal", 8, newSViv(window->immortal), 0);
	(void) hv_store(hv, "sticky_refnum", 13, newSViv(window->sticky_refnum), 0);

	(void) hv_store(hv, "data_level", 10, newSViv(window->data_level), 0);
	(void) hv_store(hv, "hilight_color", 13, new_pv(window->hilight_color), 0);

	(void) hv_store(hv, "last_timestamp", 14, newSViv(window->last_timestamp), 0);
	(void) hv_store(hv, "last_line", 9, newSViv(window->last_line), 0);

	(void) hv_store(hv, "theme", 5, plain_bless(window->theme, "Irssi::UI::Theme"), 0);
	(void) hv_store(hv, "theme_name", 10, new_pv(window->theme_name), 0);
}

static void perl_text_dest_fill_hash(HV *hv, TEXT_DEST_REC *dest)
{
	(void) hv_store(hv, "window", 6, plain_bless(dest->window, "Irssi::UI::Window"), 0);
	(void) hv_store(hv, "server", 6, iobject_bless(dest->server), 0);
	(void) hv_store(hv, "target", 6, new_pv(dest->target), 0);
	(void) hv_store(hv, "level", 5, newSViv(dest->level), 0);

	(void) hv_store(hv, "hilight_priority", 16, newSViv(dest->hilight_priority), 0);
	(void) hv_store(hv, "hilight_color", 13, new_pv(dest->hilight_color), 0);
}

static void perl_line_info_meta_fill_hash(HV *hv, LINE_INFO_META_REC *meta)
{
	GHashTableIter iter;
	char *key;
	char *val;

	if (meta != NULL) {
		if (meta->hash != NULL) {
			g_hash_table_iter_init(&iter, meta->hash);
			while (
			    g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
				(void) hv_store(hv, key, strlen(key), new_pv(val), 0);
			}
		}
		if (meta->server_time) {
			(void) hv_store(hv, "server_time", 11, newSViv(meta->server_time), 0);
		}
	}
}

static void perl_exec_fill_hash(HV *hv, EXEC_WI_REC *item)
{
	g_return_if_fail(hv != NULL);
	g_return_if_fail(item != NULL);

	perl_window_item_fill_hash(hv, (WI_ITEM_REC *) item);
	/* we don't bless to Process here to avoid infinite recursion
	   in the simplistic script binding */
	if (item->process != NULL) {
		(void) hv_store(hv, "process_id", 10, newSViv(item->process->id), 0);
	}
}

static PLAIN_OBJECT_INIT_REC fe_plains[] = {
	{ "Irssi::UI::Process", (PERL_OBJECT_FUNC) perl_process_fill_hash },
	{ "Irssi::UI::Window", (PERL_OBJECT_FUNC) perl_window_fill_hash },
	{ "Irssi::UI::TextDest", (PERL_OBJECT_FUNC) perl_text_dest_fill_hash },
	{ "Irssi::UI::LineInfoMeta", (PERL_OBJECT_FUNC) perl_line_info_meta_fill_hash },

	{ NULL, NULL }
};

MODULE = Irssi::UI  PACKAGE = Irssi::UI

PROTOTYPES: ENABLE

void
processes()
PREINIT:
	GSList *tmp;
PPCODE:
	for (tmp = processes; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(plain_bless(tmp->data, "Irssi::UI::Process")));
	}


void
init()
CODE:
	if (initialized) return;
	perl_api_version_check("Irssi::UI");
	initialized = TRUE;

        irssi_add_plains(fe_plains);
        /* window items: fe-exec */
        irssi_add_object(module_get_uniq_id_str("WINDOW ITEM TYPE", "EXEC"),
			 0, "Irssi::UI::Exec",
                         (PERL_OBJECT_FUNC) perl_exec_fill_hash);
        perl_themes_init();

void
deinit()
CODE:
	if (!initialized) return;
        perl_themes_deinit();
	initialized = FALSE;

BOOT:
	irssi_boot(UI__Formats);
	irssi_boot(UI__Themes);
	irssi_boot(UI__Window);
