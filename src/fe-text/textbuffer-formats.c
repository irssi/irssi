#include "module.h"
#include <irssi/src/core/expandos.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/refstrings.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/special-vars.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/fe-text/gui-printtext.h>
#include <irssi/src/fe-text/gui-windows.h>
#include <irssi/src/fe-text/textbuffer-formats.h>
#include <irssi/src/fe-text/textbuffer-view.h>

TEXT_BUFFER_REC *color_buf;
gboolean scrollback_format;
gboolean show_server_time;
int signal_gui_render_line_text;
GTimeZone *utc;

static void collector_free(GSList **collector)
{
	while (*collector) {
		GSList *next = (*collector)->next->next;
		i_refstr_release((*collector)->data);
		g_free((*collector)->next->data);
		g_slist_free_1((*collector)->next);
		g_slist_free_1((*collector));
		*collector = next;
	}
}

void textbuffer_format_rec_free(TEXT_BUFFER_FORMAT_REC *rec)
{
	int n;

	if (rec == NULL)
		return;
	if (rec == LINE_INFO_FORMAT_SET)
		return;

	i_refstr_release(rec->module);
	i_refstr_release(rec->format);
	i_refstr_release(rec->server_tag);
	i_refstr_release(rec->target);
	i_refstr_release(rec->nick);
	i_refstr_release(rec->address);
	if (rec->nargs >= 1) {
		i_refstr_release(rec->args[0]);
	}
	for (n = 1; n < rec->nargs; n++) {
		g_free(rec->args[n]);
	}
	rec->nargs = 0;
	g_free(rec->args);
	collector_free(&rec->expando_cache);
	g_slice_free(TEXT_BUFFER_FORMAT_REC, rec);
}

static TEXT_BUFFER_FORMAT_REC *format_rec_new(const char *module, const char *format_tag, int nargs,
                                              const char **args)
{
	int n;
	TEXT_BUFFER_FORMAT_REC *ret = g_slice_new0(TEXT_BUFFER_FORMAT_REC);
	ret->module = i_refstr_intern(module);
	ret->format = i_refstr_intern(format_tag);
	ret->nargs = nargs;
	ret->args = g_new0(char *, nargs);
	if (nargs >= 1) {
		ret->args[0] = i_refstr_intern(args[0]);
	}
	for (n = 1; n < nargs; n++) {
		ret->args[n] = g_strdup(args[n]);
	}
	return ret;
}

static void format_rec_set_dest(TEXT_BUFFER_FORMAT_REC *rec, const TEXT_DEST_REC *dest)
{
	i_refstr_release(rec->server_tag);
	i_refstr_release(rec->target);
	i_refstr_release(rec->nick);
	i_refstr_release(rec->address);
	rec->server_tag = i_refstr_intern(dest->server_tag);
	rec->target = i_refstr_intern(dest->target);
	rec->nick = i_refstr_intern(dest->nick);
	rec->address = i_refstr_intern(dest->address);
	rec->flags = dest->flags & ~PRINT_FLAG_FORMAT;
}

void textbuffer_meta_rec_free(LINE_INFO_META_REC *rec)
{
	if (rec == NULL)
		return;

	if (rec->hash != NULL)
		g_hash_table_destroy(rec->hash);

	g_free(rec);
}

static void meta_hash_create(struct _LINE_INFO_META_REC *meta)
{
	if (meta->hash == NULL) {
		meta->hash = g_hash_table_new_full(g_str_hash, (GEqualFunc) g_str_equal,
		                                   (GDestroyNotify) i_refstr_release,
		                                   (GDestroyNotify) g_free);
	}
}

static LINE_INFO_META_REC *line_meta_create(GHashTable *meta_hash)
{
	struct _LINE_INFO_META_REC *meta;
	GHashTableIter iter;
	const char *key;
	const char *val;

	if (meta_hash == NULL || g_hash_table_size(meta_hash) == 0)
		return NULL;

	meta = g_new0(struct _LINE_INFO_META_REC, 1);

	g_hash_table_iter_init(&iter, meta_hash);
	while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
		if (g_strcmp0("time", key) == 0) {
			GDateTime *time;
			if ((time = g_date_time_new_from_iso8601(val, utc)) != NULL) {
				meta->server_time = g_date_time_to_unix(time);
				g_date_time_unref(time);
			}
		} else {
			meta_hash_create(meta);
			g_hash_table_replace(meta->hash, i_refstr_intern(key), g_strdup(val));
		}
	}

	return meta;
}

static LINE_INFO_REC *store_lineinfo_tmp(TEXT_DEST_REC *dest)
{
	GUI_WINDOW_REC *gui;
	TEXT_BUFFER_VIEW_REC *view;
	TEXT_BUFFER_REC *buffer;
	LINE_INFO_REC *lineinfo;

	gui = WINDOW_GUI(dest->window);
	view = gui->view;
	buffer = view->buffer;

	lineinfo = g_new0(LINE_INFO_REC, 1);
	lineinfo->level = dest->level;
	lineinfo->time =
	    (gui->use_insert_after && gui->insert_after_time) ? gui->insert_after_time : time(NULL);

	buffer->cur_info = g_slist_prepend(buffer->cur_info, lineinfo);
	return lineinfo;
}

static void free_lineinfo_tmp(WINDOW_REC *window)
{
	GUI_WINDOW_REC *gui;
	TEXT_BUFFER_REC *buffer;
	LINE_INFO_REC *info;

	gui = WINDOW_GUI(window);
	buffer = gui->view->buffer;

	if (buffer->cur_info == NULL)
		return;

	info = buffer->cur_info->data;
	buffer->cur_info = g_slist_delete_link(buffer->cur_info, buffer->cur_info);
	textbuffer_line_info_free1(info);
	g_free(info);
}

static void sig_print_format(THEME_REC *theme, const char *module, TEXT_DEST_REC *dest,
                             void *formatnump, const char **args)
{
	int formatnum;
	FORMAT_REC *formats;
	LINE_INFO_REC *info;

	if (!scrollback_format)
		return;

	if (module == NULL)
		return;

	info = store_lineinfo_tmp(dest);

	formatnum = GPOINTER_TO_INT(formatnump);
	formats = g_hash_table_lookup(default_formats, module);

	info->format =
	    format_rec_new(module, formats[formatnum].tag, formats[formatnum].params, args);
	special_push_collector(&info->format->expando_cache);

	dest->flags |= PRINT_FLAG_FORMAT;

	signal_continue(5, theme, module, dest, formatnump, args);

	special_pop_collector();
	free_lineinfo_tmp(dest->window);
}

static void sig_print_noformat(TEXT_DEST_REC *dest, const char *text)
{
	LINE_INFO_REC *info;

	if (!scrollback_format)
		return;

	info = store_lineinfo_tmp(dest);

	info->format = format_rec_new(NULL, NULL, 2, (const char *[]){ NULL, text });
	special_push_collector(&info->format->expando_cache);

	dest->flags |= PRINT_FLAG_FORMAT;

	signal_continue(2, dest, text);

	special_pop_collector();
	free_lineinfo_tmp(dest->window);
}

static GSList *reverse_collector(GSList *a1)
{
	GSList *b1, *c1;
	c1 = NULL;
	while (a1) {
		b1 = a1->next->next;
		a1->next->next = c1;

		c1 = a1;
		a1 = b1;
	}
	return c1;
}

static void sig_gui_print_text_finished(WINDOW_REC *window, TEXT_DEST_REC *dest)
{
	GUI_WINDOW_REC *gui;
	LINE_REC *insert_after;
	LINE_INFO_REC *info;
	TEXT_BUFFER_REC *buffer;

	gui = WINDOW_GUI(window);
	buffer = gui->view->buffer;
	insert_after = gui->use_insert_after ? gui->insert_after : buffer->cur_line;

	if (buffer->cur_info == NULL)
		return;

	info = buffer->cur_info->data;

	if (info->format == NULL)
		return;

	info->format->expando_cache = reverse_collector(info->format->expando_cache);
	format_rec_set_dest(info->format, dest);

	info->meta = line_meta_create(dest->meta);

	info->level = dest->level | MSGLEVEL_FORMAT;

	/* the line will be inserted into the view with textbuffer_view_insert_line by
	   gui-printtext.c:view_add_eol */
	insert_after = textbuffer_insert(buffer, insert_after, (const unsigned char[]){}, 0, info);

	/* the TEXT_BUFFER_FORMAT_REC and meta pointer is now owned by the textbuffer */
	info->format = LINE_INFO_FORMAT_SET;
	info->meta = NULL;

	if (gui->use_insert_after)
		gui->insert_after = insert_after;
}

static void parse_colors_collector(const WINDOW_REC *window, const void *fgcolor_int,
                                   const void *bgcolor_int, const void *flags_int,
                                   const char *textpiece, const TEXT_DEST_REC *dest)
{
	int fg, bg, flags, attr;

	flags = GPOINTER_TO_INT(flags_int);
	fg = GPOINTER_TO_INT(fgcolor_int);
	bg = GPOINTER_TO_INT(bgcolor_int);
	gui_printtext_get_colors(&flags, &fg, &bg, &attr);

	if (flags & GUI_PRINT_FLAG_NEWLINE) {
		g_string_append_c(color_buf->cur_text, '\n');
	}
	format_gui_flags(color_buf->cur_text, &color_buf->last_fg, &color_buf->last_bg,
	                 &color_buf->last_flags, fg, bg, flags);

	g_string_append(color_buf->cur_text, textpiece);
}

static char *parse_colors(TEXT_DEST_REC *dest, const char *text)
{
	char *tmp;

	if (text == NULL)
		return NULL;

	color_buf = textbuffer_create(NULL);
	format_send_as_gui_flags(dest, text, (SIGNAL_FUNC) parse_colors_collector);
	tmp = g_strdup(color_buf->cur_text->str);
	textbuffer_destroy(color_buf);
	color_buf = NULL;

	return tmp;
}

static char *fallback_format(TEXT_BUFFER_FORMAT_REC *format_rec)
{
	int i;
	GString *bs;
	char *tmp;
	bs = g_string_new(NULL);
	g_string_printf(bs, "{%s#%s", format_rec->module, format_rec->format);
	for (i = 0; i < format_rec->nargs && format_rec->args[i] != NULL; i++) {
		tmp = g_strescape(format_rec->args[i], "");
		g_string_append_printf(bs, " \"%s\"", tmp);
		g_free(tmp);
	}
	g_string_append(bs, "}");
	return g_string_free(bs, FALSE);
}

char *textbuffer_line_get_text(TEXT_BUFFER_REC *buffer, LINE_REC *line, gboolean raw)
{
	TEXT_DEST_REC dest;
	GUI_WINDOW_REC *gui;
	char *tmp, *text = NULL;

	g_return_val_if_fail(buffer != NULL, NULL);
	g_return_val_if_fail(buffer->window != NULL, NULL);

	gui = WINDOW_GUI(buffer->window);
	if (line == NULL || gui == NULL)
		return NULL;

	if (line->info.level & MSGLEVEL_FORMAT && line->info.format != NULL) {
		LINE_REC *curr;
		THEME_REC *theme;
		int formatnum;
		TEXT_BUFFER_FORMAT_REC *format_rec;
		LINE_INFO_META_REC *meta;
		char *tmp2;

		curr = line;
		line = NULL;
		format_rec = curr->info.format;
		meta = curr->info.meta;

		format_create_dest_tag(
		    &dest,
		    format_rec->server_tag != NULL ? server_find_tag(format_rec->server_tag) : NULL,
		    format_rec->server_tag, format_rec->target, curr->info.level & ~MSGLEVEL_FORMAT,
		    buffer->window);
		dest.nick = format_rec->nick;
		dest.address = format_rec->address;
		dest.flags = format_rec->flags;

		theme = window_get_theme(dest.window);

		special_fill_cache(format_rec->expando_cache);
		if (format_rec->format != NULL) {
			char *arglist[MAX_FORMAT_PARAMS] = { 0 };
			formatnum = format_find_tag(format_rec->module, format_rec->format);
			memcpy(arglist, format_rec->args, format_rec->nargs * sizeof(char *));
			text = format_get_text_theme_charargs(theme, format_rec->module, &dest,
			                                      formatnum, arglist);
			if (text == NULL) {
				text = fallback_format(format_rec);
			}
		} else {
			text = g_strdup(format_rec->args[1]);
		}

		if (text != NULL && *text != '\0') {
			GString *str;

			reference_time = curr->info.time;
			if (show_server_time && meta != NULL && meta->server_time != 0) {
				current_time = meta->server_time;
			} else {
				current_time = curr->info.time;
			}

			str = g_string_new(text);
			signal_emit_id(signal_gui_render_line_text, 3, &dest, str, meta);
			if (g_strcmp0(text, str->str) == 0) {
				g_string_free(str, TRUE);
			} else {
				g_free(text);
				text = g_string_free(str, FALSE);
			}

			tmp = format_get_level_tag(theme, &dest);
			tmp2 = !theme->info_eol ? format_add_linestart(text, tmp) :
                                                  format_add_lineend(text, tmp);
			g_free_not_null(tmp);
			g_free_not_null(text);
			text = tmp2;
			tmp = format_get_line_start(theme, &dest, current_time);
			tmp2 = !theme->info_eol ? format_add_linestart(text, tmp) :
                                                  format_add_lineend(text, tmp);
			g_free_not_null(tmp);
			g_free_not_null(text);
			text = tmp2;
			/* str = g_strconcat(text, "\n", NULL); */
			/* g_free(text); */

			dest.flags |= PRINT_FLAG_FORMAT;

			reference_time = current_time = (time_t) -1;
		} else if (format_rec->format != NULL) {
			g_free(text);
			text = NULL;
		}
		special_fill_cache(NULL);
	} else {
		format_create_dest(&dest, NULL, NULL, line->info.level, buffer->window);
		text = g_strdup(line->info.text);
	}

	if (raw)
		return text;

	tmp = parse_colors(&dest, text);
	g_free(text);
	return tmp;
}

static void read_settings(void)
{
	scrollback_format = settings_get_bool("scrollback_format");
	show_server_time = settings_get_bool("show_server_time");
}

void textbuffer_formats_init(void)
{
	signal_gui_render_line_text = signal_get_uniq_id("gui render line text");
	utc = g_time_zone_new_utc();

	settings_add_bool("lookandfeel", "scrollback_format", TRUE);
	settings_add_bool("lookandfeel", "show_server_time", FALSE);

	read_settings();
	signal_add("print format", (SIGNAL_FUNC) sig_print_format);
	signal_add("print noformat", (SIGNAL_FUNC) sig_print_noformat);
	signal_add_first("gui print text finished", (SIGNAL_FUNC) sig_gui_print_text_finished);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
}

void textbuffer_formats_deinit(void)
{
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("print format", (SIGNAL_FUNC) sig_print_format);
	signal_remove("print noformat", (SIGNAL_FUNC) sig_print_noformat);
	signal_remove("gui print text finished", (SIGNAL_FUNC) sig_gui_print_text_finished);

	g_time_zone_unref(utc);
}
