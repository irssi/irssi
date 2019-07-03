#include "module.h"
#include <irssi/src/fe-text/textbuffer-formats.h>
#include <irssi/src/fe-text/textbuffer-view.h>
#include <irssi/src/fe-text/gui-printtext.h>
#include <irssi/src/fe-text/gui-windows.h>
#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/core/expandos.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/signals.h>

static int skip_next_printtext;
TEXT_BUFFER_FORMAT_REC *format_rec;

#define g_ref_string_release_opt(str) ((str) == NULL ? (void)0 : g_ref_string_release(str))

void textbuffer_format_rec_free(TEXT_BUFFER_FORMAT_REC *rec)
{
	int n;
	if (rec == NULL)
		return;
	g_ref_string_release_opt(rec->module);
	g_ref_string_release_opt(rec->format);
	g_ref_string_release_opt(rec->server_tag);
	g_ref_string_release_opt(rec->target);
	g_ref_string_release_opt(rec->nick);
	if (rec->nargs >= 1) {
		g_ref_string_release_opt(rec->args[0]);
	}
	for (n = 1; n < rec->nargs; n++) {
		g_free(rec->args[n]);
	}
	rec->nargs = 0;
	g_free(rec);
}

#define g_ref_string_new_intern_opt(str) ((str) == NULL ? NULL : g_ref_string_new_intern(str))

static TEXT_BUFFER_FORMAT_REC *format_rec_new(const char *module, const char *format_tag,
					      const char *server_tag, const char *target, const char *nick,
					      int nargs, const char **args)
{
	int n;
	TEXT_BUFFER_FORMAT_REC *ret = g_new0(TEXT_BUFFER_FORMAT_REC, 1);
	ret->module     = g_ref_string_new_intern_opt(module);
	ret->format     = g_ref_string_new_intern_opt(format_tag);
	ret->server_tag = g_ref_string_new_intern_opt(server_tag);
	ret->target     = g_ref_string_new_intern_opt(target);
	ret->nick       = g_ref_string_new_intern_opt(nick);
	ret->nargs      = nargs;
	ret->args       = g_new0(char *, nargs);
	if (nargs >= 1) {
		ret->args[0] = g_ref_string_new_intern_opt(args[0]);
	}
	for (n = 1; n < nargs; n++) {
		ret->args[n] = g_strdup(args[n]);
	}
	return ret;
}

static void sig_print_format(THEME_REC *theme, const char *module, TEXT_DEST_REC *dest, void *formatnump, const char **args)
{
	int formatnum;
	FORMAT_REC *formats;

	skip_next_printtext = TRUE;
	dest->flags |= PRINT_FLAG_FORMAT;

	formatnum = GPOINTER_TO_INT(formatnump);
	formats = g_hash_table_lookup(default_formats, module);

	textbuffer_format_rec_free(format_rec);
	format_rec = format_rec_new(module, formats[formatnum].tag, dest->server_tag, dest->target, dest->nick,
				    formats[formatnum].params, args);
	format_rec->flags  = dest->flags;
}

static void sig_print_noformat(TEXT_DEST_REC *dest, const char *text)
{
	dest->flags |= PRINT_FLAG_FORMAT;
	textbuffer_format_rec_free(format_rec);
	format_rec = format_rec_new(NULL, NULL, dest->server_tag, dest->target, dest->nick,
				    2, (const char *[]){ NULL, text });
	format_rec->flags  = dest->flags;
}

static void sig_print_text(TEXT_DEST_REC *dest, const char *text)
{
	if (skip_next_printtext) {
		skip_next_printtext = FALSE;
		return;
	}
}

static void sig_gui_print_text_finished(WINDOW_REC *window)
{
        GUI_WINDOW_REC *gui;
	TEXT_BUFFER_VIEW_REC *view;
	LINE_REC *insert_after;
	LINE_INFO_REC lineinfo = { 0 };

	static const unsigned char eol[] = { 0, LINE_CMD_EOL };

	if (format_rec == NULL)
		return;

        gui = WINDOW_GUI(window);
	view = gui->view;
	insert_after = gui->use_insert_after ?
		gui->insert_after : view->buffer->cur_line;

	lineinfo.format = format_rec;
	lineinfo.level = insert_after->info.level | MSGLEVEL_FORMAT;
	lineinfo.time = insert_after->info.time;
	format_rec = NULL;

	insert_after = textbuffer_insert(view->buffer, insert_after, eol,
					 2, &lineinfo);

	if (gui->use_insert_after)
                gui->insert_after = insert_after;
}

LINE_REC *textbuffer_reformat_line(WINDOW_REC *window, LINE_REC *line)
{
	GUI_WINDOW_REC *gui;
	LINE_REC *curr;

	gui = WINDOW_GUI(window);
	if (line == NULL)
		return NULL;

	if (line->info.level & MSGLEVEL_FORMAT) {
		TEXT_DEST_REC dest;
		THEME_REC *theme;
		int formatnum;
		TEXT_BUFFER_FORMAT_REC *format_rec;
		char *text, *tmp, *str;

		term_refresh_freeze();

		curr = line;
		line = line->prev;
		while (line != NULL && line->info.format != NULL && line->info.format == LINE_INFO_FORMAT_SET) {
			LINE_REC *prev = line->prev;
			textbuffer_view_remove_line(gui->view, line);
			line = prev;
		}
		line = NULL;
		format_rec = curr->info.format;

		format_create_dest(&dest, format_rec->server_tag != NULL ? server_find_tag(format_rec->server_tag) : NULL,
				   format_rec->target, curr->info.level & ~MSGLEVEL_FORMAT, window);

		theme = window_get_theme(dest.window);

		if (format_rec->format != NULL) {
			formatnum = format_find_tag(format_rec->module, format_rec->format);
			text = format_get_text_theme_charargs(theme, format_rec->module, &dest,
							      formatnum, format_rec->args);
		} else {
			text = g_strdup(format_rec->args[1]);
		}

		if (*text != '\0') {
			current_time = curr->info.time;

			tmp = format_get_level_tag(theme, &dest);
			str = !theme->info_eol ? format_add_linestart(text, tmp) :
				format_add_lineend(text, tmp);
			g_free_not_null(tmp);
			g_free_not_null(text);
			text = str;
			tmp = format_get_line_start(theme, &dest, curr->info.time);
			str = !theme->info_eol ? format_add_linestart(text, tmp) :
				format_add_lineend(text, tmp);
			g_free_not_null(tmp);
			g_free_not_null(text);
			text = str;
			str = g_strconcat(text, "\n", NULL);
			g_free(text);

			dest.flags |= PRINT_FLAG_FORMAT;
			gui_printtext_after_time(&dest, curr->prev, str, curr->info.time);
			g_free(str);

			current_time = (time_t)-1;
		}
		term_refresh_thaw();
		return curr;
	} else {
		return line;
	}
}

void textbuffer_formats_init(void)
{
	skip_next_printtext = FALSE;
	format_rec = NULL;

	signal_add("print format", (SIGNAL_FUNC) sig_print_format);
	signal_add("print noformat", (SIGNAL_FUNC) sig_print_noformat);
	signal_add("gui print text finished", (SIGNAL_FUNC) sig_gui_print_text_finished);
	signal_add_first("print text", (SIGNAL_FUNC) sig_print_text);
}

void textbuffer_formats_deinit(void)
{
	signal_remove("print format", (SIGNAL_FUNC) sig_print_format);
	signal_remove("print noformat", (SIGNAL_FUNC) sig_print_noformat);
	signal_remove("gui print text finished", (SIGNAL_FUNC) sig_gui_print_text_finished);
	signal_remove("print text", (SIGNAL_FUNC) sig_print_text);

	textbuffer_format_rec_free(format_rec);
}
