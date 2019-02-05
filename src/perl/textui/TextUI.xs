#define PERL_NO_GET_CONTEXT
#include "module.h"

void perl_statusbar_init(void);
void perl_statusbar_deinit(void);

static int initialized = FALSE;

static void perl_main_window_fill_hash(HV *hv, MAIN_WINDOW_REC *window)
{
	(void) hv_store(hv, "active", 6, plain_bless(window->active, "Irssi::UI::Window"), 0);

	(void) hv_store(hv, "first_line", 10, newSViv(window->first_line), 0);
	(void) hv_store(hv, "last_line", 9, newSViv(window->last_line), 0);
	(void) hv_store(hv, "width", 5, newSViv(window->width), 0);
	(void) hv_store(hv, "height", 6, newSViv(window->height), 0);

	(void) hv_store(hv, "statusbar_lines", 15, newSViv(window->statusbar_lines), 0);
}

static void perl_text_buffer_fill_hash(HV *hv, TEXT_BUFFER_REC *buffer)
{
	(void) hv_store(hv, "first_line", 10, plain_bless(buffer->first_line, "Irssi::TextUI::Line"), 0);
	(void) hv_store(hv, "lines_count", 11, newSViv(buffer->lines_count), 0);
	(void) hv_store(hv, "cur_line", 8, plain_bless(buffer->cur_line, "Irssi::TextUI::Line"), 0);
	(void) hv_store(hv, "last_eol", 8, newSViv(buffer->last_eol), 0);
}

static void perl_text_buffer_view_fill_hash(HV *hv, TEXT_BUFFER_VIEW_REC *view)
{
	(void) hv_store(hv, "buffer", 6, plain_bless(view->buffer, "Irssi::TextUI::TextBuffer"), 0);
	(void) hv_store(hv, "width", 5, newSViv(view->width), 0);
	(void) hv_store(hv, "height", 6, newSViv(view->height), 0);

	(void) hv_store(hv, "default_indent", 14, newSViv(view->default_indent), 0);
	(void) hv_store(hv, "longword_noindent", 17, newSViv(view->longword_noindent), 0);
	(void) hv_store(hv, "scroll", 6, newSViv(view->scroll), 0);

	(void) hv_store(hv, "ypos", 4, newSViv(view->ypos), 0);

	(void) hv_store(hv, "startline", 9, plain_bless(view->startline, "Irssi::TextUI::Line"), 0);
	(void) hv_store(hv, "subline", 7, newSViv(view->subline), 0);
	(void) hv_store(hv, "hidden_level", 12, newSViv(view->hidden_level), 0);

	(void) hv_store(hv, "bottom_startline", 16, plain_bless(view->bottom_startline, "Irssi::TextUI::Line"), 0);
	(void) hv_store(hv, "bottom_subline", 14, newSViv(view->bottom_subline), 0);

	(void) hv_store(hv, "empty_linecount", 15, newSViv(view->empty_linecount), 0);
	(void) hv_store(hv, "bottom", 6, newSViv(view->bottom), 0);
}

static void perl_line_fill_hash(HV *hv, LINE_REC *line)
{
	(void) hv_store(hv, "info", 4, plain_bless(&line->info, "Irssi::TextUI::LineInfo"), 0);
}

static void perl_line_cache_fill_hash(HV *hv, LINE_CACHE_REC *cache)
{
	(void) hv_store(hv, "last_access", 11, newSViv(cache->last_access), 0);
	(void) hv_store(hv, "count", 5, newSViv(cache->count), 0);
	/*LINE_CACHE_SUB_REC lines[1];*/
}

static void perl_line_info_fill_hash(HV *hv, LINE_INFO_REC *info)
{
	(void) hv_store(hv, "level", 5, newSViv(info->level), 0);
	(void) hv_store(hv, "time", 4, newSViv(info->time), 0);
}

static void perl_statusbar_item_fill_hash(HV *hv, SBAR_ITEM_REC *item)
{
	(void) hv_store(hv, "min_size", 8, newSViv(item->min_size), 0);
	(void) hv_store(hv, "max_size", 8, newSViv(item->max_size), 0);
	(void) hv_store(hv, "xpos", 4, newSViv(item->xpos), 0);
	(void) hv_store(hv, "size", 4, newSViv(item->size), 0);
	if (item->bar->parent_window != NULL)
		(void) hv_store(hv, "window", 6, plain_bless(item->bar->parent_window->active, "Irssi::UI::Window"), 0);
}

static PLAIN_OBJECT_INIT_REC textui_plains[] = {
	{ "Irssi::TextUI::MainWindow", (PERL_OBJECT_FUNC) perl_main_window_fill_hash },
	{ "Irssi::TextUI::TextBuffer", (PERL_OBJECT_FUNC) perl_text_buffer_fill_hash },
	{ "Irssi::TextUI::TextBufferView", (PERL_OBJECT_FUNC) perl_text_buffer_view_fill_hash },
	{ "Irssi::TextUI::Line", (PERL_OBJECT_FUNC) perl_line_fill_hash },
	{ "Irssi::TextUI::LineCache", (PERL_OBJECT_FUNC) perl_line_cache_fill_hash },
	{ "Irssi::TextUI::LineInfo", (PERL_OBJECT_FUNC) perl_line_info_fill_hash },
	{ "Irssi::TextUI::StatusbarItem", (PERL_OBJECT_FUNC) perl_statusbar_item_fill_hash },

	{ NULL, NULL }
};

MODULE = Irssi::TextUI  PACKAGE = Irssi::TextUI

PROTOTYPES: ENABLE

void
init()
CODE:
	if (initialized) return;
	perl_api_version_check("Irssi::TextUI");
	initialized = TRUE;

        irssi_add_plains(textui_plains);
        perl_statusbar_init();

void
deinit()
CODE:
	if (!initialized) return;
        perl_statusbar_deinit();
	initialized = FALSE;

MODULE = Irssi::TextUI PACKAGE = Irssi

void
gui_printtext(xpos, ypos, str)
	int xpos
	int ypos
	char *str

void
gui_input_set(str)
	char *str
CODE:
	gui_entry_set_text(active_entry, str);

void
gui_input_set_extent(pos, text)
	int pos
	char *text
PREINIT:
	char *tt;
CODE:
	tt = text != NULL ? format_string_expand(text, NULL) : NULL;
	gui_entry_set_extent(active_entry, pos, tt);
	g_free(tt);

void
gui_input_set_extents(pos, len, left, right)
	int pos
	int len
	char *left
	char *right
PREINIT:
	char *tl;
	char *tr;
CODE:
	tl = left != NULL ? format_string_expand(left, NULL) : NULL;
	tr = right != NULL ? format_string_expand(right, NULL) : NULL;
	gui_entry_set_extents(active_entry, pos, len, tl, tr);
	g_free(tl);
	g_free(tr);

void
gui_input_clear_extents(pos, len = 0)
	int pos
	int len
CODE:
	gui_entry_clear_extents(active_entry, pos, len);

char *
gui_input_get_extent(pos)
	int pos
CODE:
	RETVAL = gui_entry_get_extent(active_entry, pos);
OUTPUT:
	RETVAL

void
gui_input_get_text_and_extents()
PREINIT:
	GSList *ret, *tmp;
PPCODE:
	ret = gui_entry_get_text_and_extents(active_entry);
	for (tmp = ret; tmp != NULL; tmp = tmp->next) {
		XPUSHs(sv_2mortal(new_pv(tmp->data)));
	}
	g_slist_free_full(ret, g_free);

void
gui_input_set_text_and_extents(...)
PREINIT:
	GSList *list;
	int i;
PPCODE:
	list = NULL;
	for (i = items; i > 0; i--) {
		list = g_slist_prepend(list, SvPV_nolen(ST(i-1)));
	}
	gui_entry_set_text_and_extents(active_entry, list);
	g_slist_free(list);

int
gui_input_get_pos()
CODE:
	RETVAL = gui_entry_get_pos(active_entry);
OUTPUT:
	RETVAL

void
gui_input_set_pos(pos)
	int pos
CODE:
	gui_entry_set_pos(active_entry, pos);

int
wcwidth(c)
	char *c
CODE:
	if (term_type == TERM_TYPE_UTF8) {
		unichar chr = g_utf8_get_char_validated((const char *) c, -1);

		if (chr & 0x80000000) {
			RETVAL = 1;
		} else {
			RETVAL = i_wcwidth(chr);
		}
	} else if (term_type != TERM_TYPE_BIG5 ||
		   c[1] == '\0' ||
		   !is_big5((unsigned char) c[0], (unsigned char) c[1])) {
		RETVAL = i_wcwidth((unsigned char) *c);
	} else {
		RETVAL = 2;
	}
OUTPUT:
	RETVAL

MODULE = Irssi::TextUI PACKAGE = Irssi::UI::Window

void
print_after(window, prev, level, str, time = 0)
	Irssi::UI::Window window
	Irssi::TextUI::Line prev
	int level
	char *str
	time_t time
PREINIT:
	TEXT_DEST_REC dest;
	char *text;
	char *text2;
CODE:
	format_create_dest(&dest, NULL, NULL, level, window);
	text = format_string_expand(str, NULL);
	text2 = g_strconcat(text, "\n", NULL);
	gui_printtext_after_time(&dest, prev, text2, time);
	g_free(text);
	g_free(text2);

void
gui_printtext_after(window, prev, level, str, time = 0)
	Irssi::UI::Window window
	Irssi::TextUI::Line prev
	int level
	char *str
	time_t time
PREINIT:
	TEXT_DEST_REC dest;
CODE:
	format_create_dest(&dest, NULL, NULL, level, window);
	gui_printtext_after_time(&dest, prev, str, time);

Irssi::TextUI::Line
last_line_insert(window)
	Irssi::UI::Window window
CODE:
	RETVAL = WINDOW_GUI(window)->insert_after;
OUTPUT:
	RETVAL

MODULE = Irssi::TextUI PACKAGE = Irssi::Server

void
gui_printtext_after(server, target, prev, level, str, time = 0)
	Irssi::Server server
	char *target
	Irssi::TextUI::Line prev
	int level
	char *str
	time_t time
PREINIT:
	TEXT_DEST_REC dest;
CODE:
	format_create_dest(&dest, server, target, level, NULL);
	gui_printtext_after_time(&dest, prev, str, time);

BOOT:
	irssi_boot(TextUI__Statusbar);
	irssi_boot(TextUI__TextBuffer);
	irssi_boot(TextUI__TextBufferView);

MODULE = Irssi::TextUI  PACKAGE = Irssi

void
term_refresh_freeze()

void
term_refresh_thaw()
