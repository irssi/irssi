#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/fe-text/mainwindows.h>
#include <irssi/src/fe-text/sidepanels.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/queries.h>
#include <irssi/src/core/nicklist.h>
#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-common/core/window-items.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/fe-text/term.h>
#include <irssi/src/fe-common/core/formats.h>
#include <irssi/src/fe-text/module-formats.h>
#include <irssi/src/fe-common/core/themes.h>
#include <irssi/src/fe-text/gui-printtext.h>
#include <irssi/src/fe-text/textbuffer-view.h>
#include <stdarg.h>

/* Custom data level for channel events (join/part/quit/nick) */
#define DATA_LEVEL_EVENT 10

/* UTF-8 character reading function based on textbuffer-view.c */
static inline unichar read_unichar(const unsigned char *data, const unsigned char **next,
                                   int *width)
{
	unichar chr = g_utf8_get_char_validated((const char *) data, -1);
	if (chr & 0x80000000) {
		chr = 0xfffd; /* replacement character for invalid UTF-8 */
		*next = data + 1;
		*width = 1;
	} else {
		*next = (unsigned char *) g_utf8_next_char(data);
		*width = unichar_isprint(chr) ? i_wcwidth(chr) : 1;
		if (*width < 0)
			*width = 1;
	}
	return chr;
}

/* Forward declarations for static functions used before definition (C89) */
static void apply_reservations_all(void);
static void apply_and_redraw(void);
static void enable_mouse_tracking(void);
static void disable_mouse_tracking(void);
static void sp_logf(const char *fmt, ...);

static void update_left_selection_to_active(void);
static void sig_window_item_changed(WINDOW_REC *w, WI_ITEM_REC *item);
static void sig_nicklist_new(CHANNEL_REC *ch, NICK_REC *nick);
static void clear_window_full(TERM_WINDOW *tw, int width, int height);
static void renumber_windows_by_position(void);

/* Settings */
static int sp_left_width;
static int sp_right_width;
static int sp_enable_left;
static int sp_enable_right;
static int sp_auto_hide_right;
static int sp_enable_mouse;
static int sp_debug;

/* Window Priority State - Simpler approach */
typedef struct {
	WINDOW_REC *window;
	int current_priority; /* 0=none, 1=events, 2=highlight, 3=activity, 4=nick/query */
} window_priority_state;

static GHashTable *window_priorities = NULL;

static int esc_pending;
static int esc_timeout_tag = -1; /* Timer tag for ESC timeout */
static int reemit_guard;

static gboolean esc_timeout_callback(gpointer data)
{
	(void) data;
	if (esc_pending && !reemit_guard) {
		reemit_guard = 1;
		signal_emit("gui key pressed", 1, GINT_TO_POINTER(0x1b));
		reemit_guard = 0;
		esc_pending = 0;
	}
	esc_timeout_tag = -1;
	return FALSE;
}

static FILE *sp_log;
static void sp_log_open(void)
{
	if (!sp_log)
		sp_log = fopen("/tmp/irssi_sidepanels.log", "a");
}
static void sp_logf(const char *fmt, ...)
{
	va_list ap;
	if (!sp_debug)
		return;
	sp_log_open();
	if (!sp_log)
		return;
	va_start(ap, fmt);
	vfprintf(sp_log, fmt, ap);
	fprintf(sp_log, "\n");
	va_end(ap);
	fflush(sp_log);
}

static void read_settings(void)
{
	int old_mouse = sp_enable_mouse;

	sp_left_width = settings_get_int("sidepanel_left_width");
	sp_right_width = settings_get_int("sidepanel_right_width");
	sp_enable_left = settings_get_bool("sidepanel_left");
	sp_enable_right = settings_get_bool("sidepanel_right");
	sp_auto_hide_right = settings_get_bool("sidepanel_right_auto_hide");
	sp_enable_mouse = TRUE; /* always on natively */
	sp_debug = settings_get_bool("sidepanel_debug");

	/* Nick mention color is now handled through theme formats */

	apply_reservations_all();
	apply_and_redraw();
	if (!old_mouse)
		enable_mouse_tracking();
}

static void apply_reservations_all(void)
{
	GSList *tmp;
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *mw = tmp->data;
		/* reset previous reservations if any by setting negative, then apply new */
		if (mw->statusbar_columns_left)
			mainwindow_set_statusbar_columns(mw, -mw->statusbar_columns_left, 0);
		if (mw->statusbar_columns_right)
			mainwindow_set_statusbar_columns(mw, 0, -mw->statusbar_columns_right);
		/* Left panel reservations are now handled in position_tw() for better control */
		/* Don't reserve right space here - let auto-hide logic in position_tw() decide */
	}
}

static void sig_mainwindow_created(MAIN_WINDOW_REC *mw)
{
	/* Panel reservations are now handled dynamically in position_tw() for better control */
	(void) mw;
}

typedef struct {
	TERM_WINDOW *left_tw;
	TERM_WINDOW *right_tw;
	int left_w;
	int right_w;
	/* selection and scroll state */
	int left_selected_index;
	int left_scroll_offset;
	int right_selected_index;
	int right_scroll_offset;
	/* cached geometry for hit-test and drawing */
	int left_x;
	int left_y;
	int left_h;
	int right_x;
	int right_y;
	int right_h;
	/* ordered nick pointers matching rendered order */
	GSList *right_order;
} SP_MAINWIN_CTX;

static GHashTable *mw_to_ctx;

static SP_MAINWIN_CTX *get_ctx(MAIN_WINDOW_REC *mw, gboolean create)
{
	SP_MAINWIN_CTX *ctx = g_hash_table_lookup(mw_to_ctx, mw);
	if (!ctx && create) {
		ctx = g_new0(SP_MAINWIN_CTX, 1);
		g_hash_table_insert(mw_to_ctx, mw, ctx);
	}
	return ctx;
}

static void destroy_ctx(MAIN_WINDOW_REC *mw)
{
	SP_MAINWIN_CTX *ctx = g_hash_table_lookup(mw_to_ctx, mw);
	if (!ctx)
		return;
	if (ctx->left_tw) {
		term_window_destroy(ctx->left_tw);
		ctx->left_tw = NULL;
	}
	if (ctx->right_tw) {
		term_window_destroy(ctx->right_tw);
		ctx->right_tw = NULL;
	}
	if (ctx->right_order) {
		g_slist_free(ctx->right_order);
		ctx->right_order = NULL;
	}
	g_hash_table_remove(mw_to_ctx, mw);
	g_free(ctx);
}

static void position_tw(MAIN_WINDOW_REC *mw, SP_MAINWIN_CTX *ctx)
{
	int y;
	int h;
	int x;
	int w;
	gboolean show_right;
	WINDOW_REC *aw;
	y = mw->first_line + mw->statusbar_lines_top;
	h = mw->height - mw->statusbar_lines;
	if (sp_enable_left && ctx->left_w > 0) {
		/* Left panel is always at x=0, regardless of main window position */
		x = 0;
		w = ctx->left_w;
		if (ctx->left_tw) {
			/* Panel already exists, just move to correct position */
			term_window_move(ctx->left_tw, x, y, w, h);
		} else {
			/* Reserve space for left panel - this shifts main window right */
			mainwindows_reserve_columns(ctx->left_w, 0);
			ctx->left_tw = term_window_create(x, y, w, h);
			/* Force statusbar redraw to fix input box positioning */
			signal_emit("mainwindow resized", 1, mw);
		}
		ctx->left_x = x;
		ctx->left_y = y;
		ctx->left_h = h;
	} else if (ctx->left_tw) {
		/* Clear the left panel area before destroying */
		clear_window_full(ctx->left_tw, ctx->left_w, ctx->left_h);
		term_window_destroy(ctx->left_tw);
		ctx->left_tw = NULL;
		ctx->left_h = 0;
		/* Free reserved space - this shifts main window back left */
		mainwindows_reserve_columns(-ctx->left_w, 0);
		/* Force complete recreation of mainwindows to clear artifacts */
		mainwindows_recreate();
		/* Force statusbar redraw to fix input box positioning */
		signal_emit("mainwindow resized", 1, mw);
	}
	/* Auto hide right if enabled and active item doesn't contain # (not a channel) */
	show_right = sp_enable_right && ctx->right_w > 0;
	aw = mw->active;
	if (sp_auto_hide_right) {
		if (!aw || !aw->active || !aw->active->visible_name ||
		    !strchr(aw->active->visible_name, '#')) {
			show_right = FALSE;
		}
	}
	if (show_right) {
		w = ctx->right_w;
		if (ctx->right_tw) {
			/* Panel already exists, space already reserved, use current last_column */
			x = mw->last_column + 1;
			term_window_move(ctx->right_tw, x, y, w, h);
		} else {
			/* Reserve space for right panel - this shrinks main window */
			mainwindows_reserve_columns(0, ctx->right_w);
			/* After reservation, right panel should be at the new last_column + 1 */
			x = mw->last_column + 1;
			ctx->right_tw = term_window_create(x, y, w, h);
			/* Force statusbar redraw to fix input box positioning */
			signal_emit("mainwindow resized", 1, mw);
		}
		ctx->right_x = x;
		ctx->right_y = y;
		ctx->right_h = h;
	} else if (ctx->right_tw) {
		/* Clear the right panel area before destroying */
		clear_window_full(ctx->right_tw, ctx->right_w, ctx->right_h);
		term_window_destroy(ctx->right_tw);
		ctx->right_tw = NULL;
		ctx->right_h = 0;
		/* Free reserved space - this expands main window */
		mainwindows_reserve_columns(0, -ctx->right_w);
		/* Force complete recreation of mainwindows to clear artifacts */
		mainwindows_recreate();
		/* Force statusbar redraw to fix input box positioning */
		signal_emit("mainwindow resized", 1, mw);
	}
}

static void draw_border_vertical(TERM_WINDOW *tw, int width, int height, int left)
{
	(void) tw;
	(void) width;
	(void) height;
	(void) left;
}

static void draw_main_window_borders(MAIN_WINDOW_REC *mw)
{
	SP_MAINWIN_CTX *ctx = get_ctx(mw, FALSE);
	if (!ctx)
		return;

	/* Draw left border (between left panel and main window) */
	if (ctx->left_tw && ctx->left_h > 0) {
		int border_x = mw->first_column + mw->statusbar_columns_left - 1;
		for (int y = 0; y < ctx->left_h; y++) {
			gui_printtext_window_border(border_x,
			                            mw->first_line + mw->statusbar_lines_top + y);
		}
	}

	/* Draw right border (between main window and right panel) */
	if (ctx->right_tw && ctx->right_h > 0) {
		int border_x = mw->last_column + 1;
		for (int y = 0; y < ctx->right_h; y++) {
			gui_printtext_window_border(border_x,
			                            mw->first_line + mw->statusbar_lines_top + y);
		}
	}
}

/* Get or create window priority state */
static window_priority_state *get_window_priority_state(WINDOW_REC *window)
{
	window_priority_state *state;

	if (!window_priorities)
		window_priorities =
		    g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

	state = g_hash_table_lookup(window_priorities, window);
	if (!state) {
		state = g_new0(window_priority_state, 1);
		state->window = window;
		state->current_priority = 0;
		g_hash_table_insert(window_priorities, window, state);
	}
	return state;
}

/* Determine priority for new activity */
static int get_new_activity_priority(WINDOW_REC *window, int data_level)
{
	WI_ITEM_REC *item = window ? window->active : NULL;

	/* Check specific data levels in order */
	if (data_level == DATA_LEVEL_EVENT) {
		/* Channel events (join/part/quit/nick) get priority 1 (green) */
		return 1; /* Channel events */
	}

	if (data_level == DATA_LEVEL_HILIGHT) {
		/* Nick mentions get priority 4 (magenta) */
		return 4; /* Nick mention */
	}

	if (data_level == DATA_LEVEL_MSG) {
		/* Private messages always get priority 4 (magenta) */
		return 4; /* Query messages */
	}

	if (data_level == DATA_LEVEL_TEXT) {
		if (item && IS_QUERY(item)) {
			/* Query events get priority 1 (green) */
			return 1; /* Query events */
		} else {
			/* Channel text activity gets priority 3 (yellow) */
			return 3; /* Channel activity */
		}
	}

	return 0; /* No activity */
}

/* Handle new activity - core logic */
static void handle_new_activity(WINDOW_REC *window, int data_level)
{
	window_priority_state *state;
	int new_priority;
	const char *data_level_name;

	if (!window)
		return;

	/* Debug: data level name */
	switch (data_level) {
	case DATA_LEVEL_NONE:
		data_level_name = "NONE";
		break;
	case DATA_LEVEL_TEXT:
		data_level_name = "TEXT";
		break;
	case DATA_LEVEL_MSG:
		data_level_name = "MSG";
		break;
	case DATA_LEVEL_HILIGHT:
		data_level_name = "HILIGHT";
		break;
	case DATA_LEVEL_EVENT:
		data_level_name = "EVENT";
		break;
	default:
		data_level_name = "UNKNOWN";
		break;
	}

	state = get_window_priority_state(window);
	new_priority = get_new_activity_priority(window, data_level);

	/* Debug: Track all activity events - useful for diagnosing priority conflicts */
	sp_logf("ACTIVITY: Window %d data_level=%s(%d) current_priority=%d new_priority=%d",
	        window->refnum, data_level_name, data_level, state->current_priority, new_priority);

	/* Only update if new priority is higher */
	if (new_priority > state->current_priority) {
		state->current_priority = new_priority;
		/* Debug: Priority changes - essential for activity system debugging */
		sp_logf("PRIORITY: Window %d priority updated from %d to %d (type=%s)",
		        window->refnum, state->current_priority, new_priority, data_level_name);
	} else {
		/* Debug: Priority ignored - shows when lower priority events are filtered */
		sp_logf("PRIORITY: Window %d ignored - current=%d >= new=%d (type=%s)",
		        window->refnum, state->current_priority, new_priority, data_level_name);
	}
}

/* Reset window priority when user opens it */
static void reset_window_priority(WINDOW_REC *window)
{
	window_priority_state *state;

	if (!window)
		return;

	state = get_window_priority_state(window);
	if (state->current_priority > 0) {
		/* Debug: Priority reset - tracks when user opens windows */
		sp_logf("RESET: Window %d priority reset from %d to 0 (opened)", window->refnum,
		        state->current_priority);
		state->current_priority = 0;
	} else {
		/* Debug: Already reset - useful for detecting unnecessary resets */
		sp_logf("RESET: Window %d already at priority 0", window->refnum);
	}
}

static void clear_window_full(TERM_WINDOW *tw, int width, int height)
{
	int y;
	int x;
	if (!tw)
		return;
	term_set_color(tw, ATTR_RESET);
	for (y = 0; y < height; y++) {
		term_move(tw, 0, y);
		for (x = 0; x < width; x++)
			term_addch(tw, ' ');
	}
}

/* Color processing functions copied from textbuffer-view.c for proper color rendering */
#define FGATTR (ATTR_NOCOLORS | ATTR_RESETFG | FG_MASK | ATTR_FGCOLOR24)
#define BGATTR (ATTR_NOCOLORS | ATTR_RESETBG | BG_MASK | ATTR_BGCOLOR24)

static void unformat_24bit_line_color(const unsigned char **ptr, int off, int *flags,
                                      unsigned int *fg, unsigned int *bg)
{
	unsigned int color;
	unsigned char rgbx[4];
	unsigned int i;
	for (i = 0; i < 4; ++i) {
		if ((*ptr)[i + off] == '\0')
			return;
		rgbx[i] = (*ptr)[i + off];
	}
	rgbx[3] -= 0x20;
	*ptr += 4;
	for (i = 0; i < 3; ++i) {
		if (rgbx[3] & (0x10 << i))
			rgbx[i] -= 0x20;
	}
	color = rgbx[0] << 16 | rgbx[1] << 8 | rgbx[2];
	if (rgbx[3] & 0x1) {
		*flags = (*flags & FGATTR) | ATTR_BGCOLOR24;
		*bg = color;
	} else {
		*flags = (*flags & BGATTR) | ATTR_FGCOLOR24;
		*fg = color;
	}
}

static inline void unformat(const unsigned char **ptr, int *color, unsigned int *fg24,
                            unsigned int *bg24)
{
	switch (**ptr) {
	case FORMAT_STYLE_BLINK:
		*color ^= ATTR_BLINK;
		break;
	case FORMAT_STYLE_UNDERLINE:
		*color ^= ATTR_UNDERLINE;
		break;
	case FORMAT_STYLE_BOLD:
		*color ^= ATTR_BOLD;
		break;
	case FORMAT_STYLE_REVERSE:
		*color ^= ATTR_REVERSE;
		break;
	case FORMAT_STYLE_ITALIC:
		*color ^= ATTR_ITALIC;
		break;
	case FORMAT_STYLE_MONOSPACE:
		/* *color ^= ATTR_MONOSPACE; */
		break;
	case FORMAT_STYLE_DEFAULTS:
		*color = ATTR_RESET;
		break;
	case FORMAT_STYLE_CLRTOEOL:
		break;
#define SET_COLOR_EXT_FG_BITS(base, pc)                                                            \
	*color &= ~ATTR_FGCOLOR24;                                                                 \
	*color = (*color & BGATTR) | (base + *pc - FORMAT_COLOR_NOCHANGE)
#define SET_COLOR_EXT_BG_BITS(base, pc)                                                            \
	*color &= ~ATTR_BGCOLOR24;                                                                 \
	*color = (*color & FGATTR) | ((base + *pc - FORMAT_COLOR_NOCHANGE) << BG_SHIFT)
	case FORMAT_COLOR_EXT1:
		SET_COLOR_EXT_FG_BITS(0x10, ++*ptr);
		break;
	case FORMAT_COLOR_EXT1_BG:
		SET_COLOR_EXT_BG_BITS(0x10, ++*ptr);
		break;
	case FORMAT_COLOR_EXT2:
		SET_COLOR_EXT_FG_BITS(0x60, ++*ptr);
		break;
	case FORMAT_COLOR_EXT2_BG:
		SET_COLOR_EXT_BG_BITS(0x60, ++*ptr);
		break;
	case FORMAT_COLOR_EXT3:
		SET_COLOR_EXT_FG_BITS(0xb0, ++*ptr);
		break;
	case FORMAT_COLOR_EXT3_BG:
		SET_COLOR_EXT_BG_BITS(0xb0, ++*ptr);
		break;
#undef SET_COLOR_EXT_BG_BITS
#undef SET_COLOR_EXT_FG_BITS
	case FORMAT_COLOR_24:
		unformat_24bit_line_color(ptr, 1, color, fg24, bg24);
		break;
	default:
		if (**ptr != FORMAT_COLOR_NOCHANGE) {
			if (**ptr == (unsigned char) 0xff) {
				*color = (*color & BGATTR) | ATTR_RESETFG;
			} else {
				*color = (*color & BGATTR) | (((unsigned char) **ptr - '0') & 0xf);
			}
		}
		if ((*ptr)[1] == '\0')
			break;

		(*ptr)++;
		if (**ptr != FORMAT_COLOR_NOCHANGE) {
			if (**ptr == (unsigned char) 0xff) {
				*color = (*color & FGATTR) | ATTR_RESETBG;
			} else {
				*color = (*color & FGATTR) |
				         ((((unsigned char) **ptr - '0') & 0xf) << BG_SHIFT);
			}
		}
	}
	if (**ptr == '\0')
		return;
}

static void draw_str_themed(TERM_WINDOW *tw, int x, int y, WINDOW_REC *wctx, int format_id,
                            const char *text)
{
	TEXT_DEST_REC dest;
	THEME_REC *theme;
	char *out, *expanded;
	const unsigned char *ptr;
	const unsigned char *next_ptr;
	int color;
	int char_width;
	unsigned int fg24, bg24;
	unichar chr;

	format_create_dest(&dest, NULL, NULL, 0, wctx);
	theme = window_get_theme(wctx);
	out = format_get_text_theme(theme, MODULE_NAME, &dest, format_id, text);
	/* Debug: Uncomment to trace theme format rendering issues */
	// sp_logf("THEME_DEBUG: format_id=%d text='%s' out='%s'", format_id, text ? text :
	// "(null)", out ? out : "(null)");

	if (out != NULL && *out != '\0') {
		/* Convert theme color codes and render with proper color handling */
		expanded = format_string_expand(out, NULL);

		/* Initialize color state */
		color = ATTR_RESET;
		fg24 = bg24 = UINT_MAX;
		ptr = (const unsigned char *) expanded;

		term_move(tw, x, y);
		term_set_color(tw, ATTR_RESET);

		/* Process each character with color codes (like textbuffer-view.c) */
		while (*ptr != '\0') {
			if (*ptr == 4) {
				/* Format code - process color change */
				ptr++;
				if (*ptr == '\0')
					break;
				unformat(&ptr, &color, &fg24, &bg24);
				term_set_color2(tw, color, fg24, bg24);
				ptr++;
				continue;
			}

			/* Regular character - read UTF-8 properly */
			chr = read_unichar(ptr, &next_ptr, &char_width);

			if (unichar_isprint(chr)) {
				term_add_unichar(tw, chr);
			}
			ptr = next_ptr;
		}

		g_free(expanded);
	} else {
		/* Fallback: display plain text if theme formatting fails */
		term_move(tw, x, y);
		term_addstr(tw, text ? text : "");
	}
	g_free(out);
}

/*
 * NEW DUAL-PARAMETER THEME FORMATS FOR NICKLIST CUSTOMIZATION
 *
 * The new *_status formats allow separate styling of status symbols and nicks:
 *
 * Example theme customization:
 *
 * "fe-text" = {
 *   # Different colors for @ symbol vs nick:
 *   sidepanel_nick_op_status = "%R$0%Y$1";        # Red @ + Yellow nick
 *
 *   # Decorative brackets around status:
 *   sidepanel_nick_op_status = "%Y[$0]%N$1";      # [@]nick
 *
 *   # Hide status completely (just colorized nick):
 *   sidepanel_nick_op_status = "%Y$1";            # Only yellow nick, no @
 *
 *   # Custom symbols instead of @ and +:
 *   sidepanel_nick_op_status = "%R⚡%N%Y$1";       # ⚡nick instead of @nick
 *   sidepanel_nick_voice_status = "%C◆%N%c$1";    # ◆nick instead of +nick
 * };
 */
static void draw_str_themed_2params(TERM_WINDOW *tw, int x, int y, WINDOW_REC *wctx, int format_id,
                                    const char *param1, const char *param2)
{
	TEXT_DEST_REC dest;
	THEME_REC *theme;
	char *out, *expanded;
	const unsigned char *ptr;
	const unsigned char *next_ptr;
	int color;
	int char_width;
	unsigned int fg24, bg24;
	unichar chr;
	char *args[3];

	format_create_dest(&dest, NULL, NULL, 0, wctx);
	theme = window_get_theme(wctx);

	/* Create args array for format_get_text_theme_charargs */
	args[0] = (char *) param1;
	args[1] = (char *) param2;
	args[2] = NULL;

	out = format_get_text_theme_charargs(theme, MODULE_NAME, &dest, format_id, args);
	/* Debug: Uncomment to trace 2-parameter theme format rendering */
	// sp_logf("THEME_DEBUG_2P: format_id=%d param1='%s' param2='%s' out='%s'",
	//        format_id, param1 ? param1 : "(null)", param2 ? param2 : "(null)", out ? out :
	//        "(null)");

	if (out != NULL && *out != '\0') {
		/* Convert theme color codes and render with proper color handling */
		expanded = format_string_expand(out, NULL);

		/* Initialize color state */
		color = ATTR_RESET;
		fg24 = bg24 = UINT_MAX;
		ptr = (const unsigned char *) expanded;

		term_move(tw, x, y);
		term_set_color(tw, ATTR_RESET);

		/* Process each character with color codes (like textbuffer-view.c) */
		while (*ptr != '\0') {
			if (*ptr == 4) {
				/* Format code - process color change */
				ptr++;
				if (*ptr == '\0')
					break;
				unformat(&ptr, &color, &fg24, &bg24);
				term_set_color2(tw, color, fg24, bg24);
				ptr++;
				continue;
			}

			/* Regular character - read UTF-8 properly */
			chr = read_unichar(ptr, &next_ptr, &char_width);

			if (unichar_isprint(chr)) {
				term_add_unichar(tw, chr);
			}
			ptr = next_ptr;
		}

		g_free(expanded);
	} else {
		/* Fallback: display plain text if theme formatting fails */
		term_move(tw, x, y);
		term_addstr(tw, param1 ? param1 : "");
		term_addstr(tw, param2 ? param2 : "");
	}
	g_free(out);
}

/* Renumber all windows according to sorted display order */
typedef struct {
	WINDOW_REC *win;
	int sort_group; /* 0=Notices, 1=server, 2=channel, 3=query, 4=named_orphan, 5=unnamed_orphan
	                 */
	char *sort_key; /* For alphabetical sorting within group */
	SERVER_REC *server; /* Server for grouping */
} WINDOW_SORT_REC;

static gint compare_window_sort_items(gconstpointer a, gconstpointer b)
{
	WINDOW_SORT_REC *w1 = (WINDOW_SORT_REC *) a;
	WINDOW_SORT_REC *w2 = (WINDOW_SORT_REC *) b;
	const char *net1, *net2;
	int server_cmp;

	/* 1. Notices always comes first */
	if (w1->sort_group == 0)
		return -1; /* w1 is Notices */
	if (w2->sort_group == 0)
		return 1; /* w2 is Notices */

	/* 2. Sort by server (alphabetically) */
	if (w1->server && w2->server) {
		net1 = w1->server->connrec && w1->server->connrec->chatnet ?
		           w1->server->connrec->chatnet :
		           (w1->server->connrec ? w1->server->connrec->address : "server");
		net2 = w2->server->connrec && w2->server->connrec->chatnet ?
		           w2->server->connrec->chatnet :
		           (w2->server->connrec ? w2->server->connrec->address : "server");
		server_cmp = g_ascii_strcasecmp(net1 ? net1 : "", net2 ? net2 : "");
		if (server_cmp != 0)
			return server_cmp;
	} else if (w1->server && !w2->server) {
		return -1; /* Server windows come before non-server windows */
	} else if (!w1->server && w2->server) {
		return 1; /* Server windows come before non-server windows */
	}

	/* 3. Within same server, sort by type: server status < channels < queries < orphans */
	if (w1->sort_group != w2->sort_group) {
		return w1->sort_group - w2->sort_group;
	}

	/* 4. Within same type, sort alphabetically by name */
	return g_ascii_strcasecmp(w1->sort_key ? w1->sort_key : "",
	                          w2->sort_key ? w2->sort_key : "");
}

/* Build sorted list of windows according to user rules - shared by all functions */
static GSList *build_sorted_window_list(void)
{
	GSList *w, *sort_list = NULL;

	/* Create sorted list of all windows according to user rules */
	for (w = windows; w; w = w->next) {
		WINDOW_REC *win = w->data;
		WINDOW_SORT_REC *sort_rec = g_new0(WINDOW_SORT_REC, 1);
		const char *win_name;

		sort_rec->win = win;
		/* Try to find server for this window */
		if (win->active && win->active->server) {
			sort_rec->server = win->active->server;
		} else {
			/* For server status windows, try to find server by servertag */
			sort_rec->server = win->servertag ? server_find_tag(win->servertag) : NULL;
		}

		win_name = window_get_active_name(win);

		/* Determine sort group and key according to user rules */
		if (win_name && g_ascii_strcasecmp(win_name, "Notices") == 0) {
			/* 1. Notices window - always first */
			sort_rec->sort_group = 0;
			sort_rec->sort_key = g_strdup("Notices");
		} else if (sort_rec->server && !win->active) {
			/* 2. Server status windows - no active channel/query */
			const char *net;
			sort_rec->sort_group = 1;
			net = sort_rec->server->connrec && sort_rec->server->connrec->chatnet ?
			          sort_rec->server->connrec->chatnet :
			          (sort_rec->server->connrec ? sort_rec->server->connrec->address :
			                                       "server");
			sort_rec->sort_key = g_strdup(net ? net : "server");
		} else if (win->active && win->active->server) {
			/* Windows with active channel/query items */
			WI_ITEM_REC *item = win->active;
			sort_rec->server = item->server; /* Use server from active item */
			if (IS_CHANNEL(item)) {
				/* 3. Channels - alphabetically within server */
				sort_rec->sort_group = 2;
				sort_rec->sort_key = g_strdup(item->name ? item->name : "channel");
			} else if (IS_QUERY(item)) {
				/* 4. Queries - alphabetically within server */
				sort_rec->sort_group = 3;
				sort_rec->sort_key = g_strdup(item->name ? item->name : "query");
			} else {
				/* Other server-related items */
				sort_rec->sort_group = 2;
				sort_rec->sort_key = g_strdup(item->name ? item->name : "item");
			}
		} else if (win_name && win_name[0] != '\0') {
			/* 5. Named orphan windows (not connected to any server) */
			sort_rec->sort_group = 4;
			sort_rec->sort_key = g_strdup(win_name);
		} else {
			/* 6. Unnamed orphan windows */
			sort_rec->sort_group = 5;
			sort_rec->sort_key = g_strdup_printf("window_%d", win->refnum);
		}

		sort_list = g_slist_append(sort_list, sort_rec);
	}

	/* Sort according to our rules */
	sort_list = g_slist_sort(sort_list, compare_window_sort_items);

	return sort_list;
}

/* Free sorted window list */
static void free_sorted_window_list(GSList *sort_list)
{
	GSList *s;
	for (s = sort_list; s; s = s->next) {
		WINDOW_SORT_REC *sort_rec = s->data;
		g_free(sort_rec->sort_key);
		g_free(sort_rec);
	}
	g_slist_free(sort_list);
}

static void renumber_windows_by_position(void)
{
	GSList *sort_list, *s;
	int position = 1;

	/* Get sorted list using shared function */
	sort_list = build_sorted_window_list();

	/* Renumber all windows according to sorted order */
	for (s = sort_list; s; s = s->next) {
		WINDOW_SORT_REC *sort_rec = s->data;
		WINDOW_REC *win = sort_rec->win;

		if (win->refnum != position) {
			window_set_refnum(win, position);
		}
		position++;
	}

	/* Clean up */
	free_sorted_window_list(sort_list);
}

static gint ci_nick_compare(gconstpointer a, gconstpointer b)
{
	NICK_REC *n1 = (NICK_REC *) a;
	NICK_REC *n2 = (NICK_REC *) b;
	if (!n1 || !n1->nick)
		return 1;
	if (!n2 || !n2->nick)
		return -1;
	return g_ascii_strcasecmp(n1->nick, n2->nick);
}

static void draw_left_contents(MAIN_WINDOW_REC *mw, SP_MAINWIN_CTX *ctx)
{
	TERM_WINDOW *tw;
	int row;
	int skip;
	int height;
	GSList *sort_list, *s;
	int list_index;

	if (!ctx)
		return;
	tw = ctx->left_tw;
	if (!tw)
		return;
	clear_window_full(tw, ctx->left_w, ctx->left_h);

	row = 0;
	skip = ctx->left_scroll_offset;
	height = ctx->left_h;

	/* Get sorted list using shared function */
	sort_list = build_sorted_window_list();

	/* Draw windows in sorted order */
	list_index = 0;
	for (s = sort_list; s && row < height; s = s->next) {
		WINDOW_SORT_REC *sort_rec = s->data;
		WINDOW_REC *win = sort_rec->win;
		const char *display_name = sort_rec->sort_key;
		int activity = win->data_level;
		int format;

		/* Skip items before our scroll offset */
		if (list_index++ < skip)
			continue;

		/* Determine format based on selection and activity */
		if (win->refnum - 1 == ctx->left_selected_index) {
			format = TXT_SIDEPANEL_ITEM_SELECTED;
		} else if (sort_rec->sort_group == 0 || sort_rec->sort_group == 1) {
			/* Notices and server status windows use header format unless selected */
			if (activity >= DATA_LEVEL_HILIGHT) {
				/* Check if this is a nick mention (has hilight_color indicating
				 * nick mention) */
				if (win->hilight_color != NULL) {
					format = TXT_SIDEPANEL_ITEM_NICK_MENTION;
				} else {
					format = TXT_SIDEPANEL_ITEM_HIGHLIGHT;
				}
			} else if (activity > DATA_LEVEL_NONE) {
				format = TXT_SIDEPANEL_ITEM_ACTIVITY;
			} else {
				format = TXT_SIDEPANEL_HEADER;
			}
		} else {
			/* Channels, queries, and other windows - SIMPLE PRIORITY SYSTEM */
			window_priority_state *state = get_window_priority_state(win);
			int current_priority = state->current_priority;

			switch (current_priority) {
			case 4: /* PRIORITY 4: Nick mention OR Query messages (magenta) */
				/* Use QUERY_MSG only for query windows, NICK_MENTION for channel
				 * mentions */
				if (win->active && IS_QUERY(win->active)) {
					format = TXT_SIDEPANEL_ITEM_QUERY_MSG;
				} else {
					format = TXT_SIDEPANEL_ITEM_NICK_MENTION;
				}
				break;
			case 3: /* PRIORITY 3: Channel activity (yellow) */
				format = TXT_SIDEPANEL_ITEM_ACTIVITY;
				break;
			case 2: /* PRIORITY 2: Keyword highlights (red) */
				format = TXT_SIDEPANEL_ITEM_HIGHLIGHT;
				break;
			case 1: /* PRIORITY 1: Events (green) */
				format = TXT_SIDEPANEL_ITEM_EVENTS;
				break;
			default: /* PRIORITY 0: No activity (normal) */
				format = TXT_SIDEPANEL_ITEM;
				break;
			}
		}

		/* Draw the item */
		term_move(tw, 0, row);
		draw_str_themed(tw, 0, row, mw->active, format,
		                display_name ? display_name : "window");
		row++;
	}

	/* Clean up */
	free_sorted_window_list(sort_list);

	/* Only draw border if right panel is also visible */
	if (ctx->right_tw && ctx->right_h > 0) {
		draw_border_vertical(tw, ctx->left_w, ctx->left_h, 1);
	}
	irssi_set_dirty();
}

static void draw_right_contents(MAIN_WINDOW_REC *mw, SP_MAINWIN_CTX *ctx)
{
	TERM_WINDOW *tw;
	WINDOW_REC *aw;
	int height;
	int skip;
	int index;
	int row;
	GSList *nt;
	if (!ctx)
		return;
	tw = ctx->right_tw;
	if (!tw)
		return;
	clear_window_full(tw, ctx->right_w, ctx->right_h);
	aw = mw->active;
	height = ctx->right_h;
	skip = ctx->right_scroll_offset;
	index = 0;
	row = 0;
	if (ctx->right_order) {
		g_slist_free(ctx->right_order);
		ctx->right_order = NULL;
	}

	/* If no channel active (no # in name), just draw border and return */
	if (!aw || !aw->active || !aw->active->visible_name ||
	    !strchr(aw->active->visible_name, '#')) {
		draw_border_vertical(tw, ctx->right_w, ctx->right_h, 0);
		irssi_set_dirty();
		return;
	}
	{
		CHANNEL_REC *ch = CHANNEL(aw->active);
		GSList *nicks = nicklist_getnicks(ch);
		GSList *ops = NULL, *voices = NULL, *normal = NULL;
		GSList *cur;
		/* Split nicks by status */
		for (nt = nicks; nt; nt = nt->next) {
			NICK_REC *nick = nt->data;
			if (!nick || !nick->nick)
				continue;
			if (nick->op)
				ops = g_slist_prepend(ops, nick);
			else if (nick->voice)
				voices = g_slist_prepend(voices, nick);
			else
				normal = g_slist_prepend(normal, nick);
		}
		/* Sort each group alphabetically */
		ops = g_slist_sort(ops, ci_nick_compare);
		voices = g_slist_sort(voices, ci_nick_compare);
		normal = g_slist_sort(normal, ci_nick_compare);
		/* Build ordered list and render */
		for (cur = ops; cur && row < height; cur = cur->next) {
			NICK_REC *nick = cur->data;
			int format;
			ctx->right_order = g_slist_append(ctx->right_order, nick);
			if (index++ < skip)
				continue;
			term_move(tw, 1, row);
			format = TXT_SIDEPANEL_NICK_OP_STATUS;
			draw_str_themed_2params(tw, 1, row, mw->active, format, "@", nick->nick);
			row++;
		}
		for (cur = voices; cur && row < height; cur = cur->next) {
			NICK_REC *nick = cur->data;
			int format;
			ctx->right_order = g_slist_append(ctx->right_order, nick);
			if (index++ < skip)
				continue;
			term_move(tw, 1, row);
			format = TXT_SIDEPANEL_NICK_VOICE_STATUS;
			draw_str_themed_2params(tw, 1, row, mw->active, format, "+", nick->nick);
			row++;
		}
		for (cur = normal; cur && row < height; cur = cur->next) {
			NICK_REC *nick = cur->data;
			int format;
			ctx->right_order = g_slist_append(ctx->right_order, nick);
			if (index++ < skip)
				continue;
			term_move(tw, 1, row);
			format = TXT_SIDEPANEL_NICK_NORMAL_STATUS;
			draw_str_themed_2params(tw, 1, row, mw->active, format, "", nick->nick);
			row++;
		}
		g_slist_free(ops);
		g_slist_free(voices);
		g_slist_free(normal);
	}
	draw_border_vertical(tw, ctx->right_w, ctx->right_h, 0);
	irssi_set_dirty();
}

static void redraw_one(MAIN_WINDOW_REC *mw)
{
	SP_MAINWIN_CTX *ctx = get_ctx(mw, FALSE);
	if (!ctx)
		return;
	position_tw(mw, ctx);
	draw_left_contents(mw, ctx);
	/* Only draw right contents if right panel is actually shown */
	if (ctx->right_tw && ctx->right_h > 0) {
		draw_right_contents(mw, ctx);
	}
	draw_main_window_borders(mw);
	irssi_set_dirty();
	term_refresh(NULL);
}

static void redraw_all(void)
{
	GSList *t;
	for (t = mainwindows; t; t = t->next)
		redraw_one(t->data);
}

static void sig_mainwindow_resized(MAIN_WINDOW_REC *mw)
{
	redraw_one(mw);
}

static void sig_window_changed(WINDOW_REC *w)
{
	/* Reset priority when user opens/switches to window */
	if (w) {
		WI_ITEM_REC *item = w ? w->active : NULL;
		const char *item_name = item ? item->visible_name : "NULL";
		/* Debug: Window switching - tracks user navigation */
		sp_logf("SIGNAL: window_changed from %d to %d '%s' (USER SWITCHED)",
		        active_win ? active_win->refnum : -1, w->refnum, item_name);
		reset_window_priority(w);
	}
	update_left_selection_to_active();
	redraw_all();
}

static void sig_window_item_changed(WINDOW_REC *w, WI_ITEM_REC *item)
{
	const char *item_name = item ? item->visible_name : "NULL";
	const char *item_type = item ? (IS_QUERY(item)   ? "QUERY" :
	                                IS_CHANNEL(item) ? "CHANNEL" :
	                                                   "OTHER") :
	                               "NONE";

	/* Debug: Window item changes - tracks channel/query switching */
	sp_logf("SIGNAL: window_item_changed Window %d item '%s' (%s) active_win=%d",
	        w ? w->refnum : -1, item_name, item_type, active_win ? active_win->refnum : -1);

	update_left_selection_to_active();
	redraw_all();
}

static void sig_window_created(WINDOW_REC *window)
{
	(void) window;
	renumber_windows_by_position();
	redraw_all();
}

static void sig_window_destroyed(WINDOW_REC *window)
{
	(void) window;
	renumber_windows_by_position();
	redraw_all();
}

static void sig_window_item_new(WINDOW_REC *window, WI_ITEM_REC *item)
{
	(void) window;
	(void) item;
	renumber_windows_by_position();
	redraw_all();
}

static void sig_query_created(QUERY_REC *query, int automatic)
{
	(void) query;
	(void) automatic;
	renumber_windows_by_position();
	redraw_all();
}

static void sig_channel_joined(CHANNEL_REC *channel)
{
	(void) channel;
	renumber_windows_by_position();
	redraw_all();
}

static void sig_nicklist_changed(CHANNEL_REC *channel, NICK_REC *nick, const char *old_nick)
{
	/* Nicklist changes don't trigger activity - just redraw */
	(void) channel;
	(void) nick;
	(void) old_nick;
	redraw_all();
}

static void sig_nicklist_new(CHANNEL_REC *channel, NICK_REC *nick)
{
	/* Nicklist changes don't trigger activity - just redraw */
	(void) channel;
	(void) nick;
	redraw_all();
}

/* Print text signal handler - get accurate data levels */
static void sig_print_text(TEXT_DEST_REC *dest, const char *msg)
{
	WINDOW_REC *window;
	WI_ITEM_REC *item;
	int data_level;
	const char *item_name, *item_type;

	if (!dest || !dest->window)
		return;

	window = dest->window;

	/* Skip if this is the active window */
	if (window == active_win)
		return;

	/* Filter out message levels that are handled by dedicated signals to avoid duplicates */
	if (dest->level & (MSGLEVEL_JOINS | MSGLEVEL_PARTS | MSGLEVEL_QUITS | MSGLEVEL_KICKS |
	                   MSGLEVEL_MODES | MSGLEVEL_TOPICS | MSGLEVEL_NICKS | MSGLEVEL_ACTIONS)) {
		/* These are handled by message_join/part/quit/nick signals - skip to avoid
		 * duplicates */
		return;
	}

	/* Determine actual data level based on message level - same logic as window-activity.c */
	if (dest->level & MSGLEVEL_HILIGHT) {
		data_level = DATA_LEVEL_HILIGHT;
	} else if (dest->level & (MSGLEVEL_MSGS | MSGLEVEL_NOTICES)) {
		/* Check if this is a query or channel */
		item = window->active;
		if (item && IS_QUERY(item)) {
			data_level = DATA_LEVEL_MSG; /* Query messages */
		} else {
			data_level = DATA_LEVEL_TEXT; /* Channel messages */
		}
	} else if (dest->level & MSGLEVEL_PUBLIC) {
		data_level = DATA_LEVEL_TEXT; /* Public channel text */
	} else {
		data_level = DATA_LEVEL_TEXT; /* Default to text level */
	}

	/* Debug logging */
	item = window->active;
	item_name = item ? item->visible_name : "NULL";
	item_type = item ? (IS_QUERY(item)   ? "QUERY" :
	                    IS_CHANNEL(item) ? "CHANNEL" :
	                                       "OTHER") :
	                   "NONE";

	/* Debug: Text messages - essential for activity classification debugging */
	sp_logf("SIGNAL: print_text Window %d '%s' (%s) msg_level=0x%x data_level=%d active_win=%d",
	        window->refnum, item_name, item_type, dest->level, data_level,
	        active_win ? active_win->refnum : -1);

	handle_new_activity(window, data_level);
	redraw_all();
}

/* Event signal handlers for join/part/quit/nick - priority 1 events */
static void sig_message_join(SERVER_REC *server, const char *channel, const char *nick,
                             const char *address, const char *account, const char *realname)
{
	WINDOW_REC *window = window_find_item(server, channel);
	if (window) {
		/* Debug: Join events - tracks channel join activity */
		sp_logf("SIGNAL: message_join %s on %s (Window %d) active_win=%d", nick, channel,
		        window->refnum, active_win ? active_win->refnum : -1);
		handle_new_activity(window, DATA_LEVEL_EVENT);
	}
	redraw_all();
}

static void sig_message_part(SERVER_REC *server, const char *channel, const char *nick,
                             const char *address, const char *reason)
{
	WINDOW_REC *window = window_find_item(server, channel);
	if (window) {
		/* Debug: Part events - tracks channel part activity */
		sp_logf("SIGNAL: message_part %s from %s (Window %d) active_win=%d", nick, channel,
		        window->refnum, active_win ? active_win->refnum : -1);
		handle_new_activity(window, DATA_LEVEL_EVENT);
	}
	redraw_all();
}

static void sig_message_quit(SERVER_REC *server, const char *nick, const char *address,
                             const char *reason)
{
	/* Handle quit for all windows where this nick was present */
	GSList *tmp;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *window = tmp->data;
		if (window->active && window->active->server == server) {
			handle_new_activity(window, DATA_LEVEL_EVENT);
		}
	}
	redraw_all();
}

static void sig_message_nick(SERVER_REC *server, const char *newnick, const char *oldnick,
                             const char *address)
{
	/* Handle nick change for all windows on this server */
	GSList *tmp;
	for (tmp = windows; tmp != NULL; tmp = tmp->next) {
		WINDOW_REC *window = tmp->data;
		if (window->active && window->active->server == server) {
			handle_new_activity(window, DATA_LEVEL_EVENT);
		}
	}
	redraw_all();
}

static void setup_ctx_for(MAIN_WINDOW_REC *mw)
{
	SP_MAINWIN_CTX *ctx;
	ctx = get_ctx(mw, TRUE);
	ctx->left_w = (sp_enable_left ? sp_left_width : 0);
	ctx->right_w = (sp_enable_right ? sp_right_width : 0);
	position_tw(mw, ctx);
}

static void update_left_selection_to_active(void)
{
	GSList *tmp;

	for (tmp = mainwindows; tmp; tmp = tmp->next) {
		MAIN_WINDOW_REC *mw = tmp->data;
		SP_MAINWIN_CTX *ctx = get_ctx(mw, FALSE);
		WINDOW_REC *aw = mw->active;

		if (!ctx || !aw)
			continue;

		/* Simple: selection index = active window refnum - 1 (0-based indexing) */
		ctx->left_selected_index = aw->refnum - 1;
	}
}

static void apply_and_redraw(void)
{
	GSList *tmp;
	for (tmp = mainwindows; tmp; tmp = tmp->next) {
		MAIN_WINDOW_REC *mw = tmp->data;
		setup_ctx_for(mw);
	}
	redraw_all();
}

/* Simple mouse parser state for SGR (1006) mode: ESC [ < btn ; x ; y M/m */
static gboolean mouse_tracking_enabled = FALSE;
static int mouse_state = 0; /* 0 idle, >0 reading sequence */
static char mouse_buf[64];
static int mouse_len = 0;

static gboolean handle_click_at(int x, int y, int button)
{
	GSList *mt;
	/* Debug: Mouse clicks - useful for mouse interaction debugging */
	sp_logf("MOUSE_CLICK: at x=%d y=%d button=%d", x, y, button);
	for (mt = mainwindows; mt; mt = mt->next) {
		MAIN_WINDOW_REC *mw = mt->data;
		SP_MAINWIN_CTX *ctx = get_ctx(mw, FALSE);
		if (!ctx)
			continue;
		if (ctx->left_tw) {
			int px = ctx->left_x, py = ctx->left_y, pw = ctx->left_w, ph = ctx->left_h;
			if (x >= px && x < px + pw && y >= py && y < py + ph) {
				int row = y - py;
				int target_index = row + ctx->left_scroll_offset;
				int idx = 0;
				GSList *sort_list, *s;

				/* Get sorted list using shared function */
				sort_list = build_sorted_window_list();

				/* Find the window at target_index */
				for (s = sort_list; s; s = s->next) {
					if (idx++ == target_index) {
						WINDOW_SORT_REC *sort_rec = s->data;
						WINDOW_REC *win = sort_rec->win;

						/* Debug: Window switches via mouse - tracks click
						 * navigation */
						sp_logf(
						    "MOUSE_CLICK: switching to window %d (was %d)",
						    win ? win->refnum : -1,
						    active_win ? active_win->refnum : -1);
						ctx->left_selected_index = target_index;
						if (win)
							window_set_active(win);
						redraw_one(mw);
						irssi_set_dirty();
						free_sorted_window_list(sort_list);
						return TRUE;
					}
				}

				free_sorted_window_list(sort_list);
			}
		}
		if (ctx->right_tw) {
			int px = ctx->right_x, py = ctx->right_y, pw = ctx->right_w,
			    ph = ctx->right_h;
			if (x >= px && x < px + pw && y >= py && y < py + ph) {
				int row = y - py;
				WINDOW_REC *aw = mw->active;
				if (aw && IS_CHANNEL(aw->active)) {
					CHANNEL_REC *ch = CHANNEL(aw->active);
					int target_index = ctx->right_scroll_offset + row;
					int count = g_slist_length(ctx->right_order);
					if (target_index >= 0 && target_index < count) {
						NICK_REC *nick = g_slist_nth_data(ctx->right_order,
						                                  target_index);
						ctx->right_selected_index = target_index;
						if (nick && nick->nick)
							signal_emit("command query", 3, nick->nick,
							            ch->server, ch);
						redraw_one(mw);
						irssi_set_dirty();
						return TRUE;
					}
				}
			}
		}
	}
	return FALSE;
}

gboolean sidepanels_try_parse_mouse_key(unichar key)
{
	char *s;
	char *sc1;
	char *sc2;
	char *end;
	char last;
	int braw;
	int x;
	int y;
	gboolean press;
	GSList *mt;

	if (!sp_enable_mouse)
		return FALSE;
	if (reemit_guard)
		return FALSE; /* Don't process re-emitted keys */
	if (mouse_state == 0) {
		if (key == 0x1b) {
			mouse_state = 1;
			mouse_len = 0;
			esc_pending = 1;
			/* Start timeout to distinguish fast mouse ESC from user ESC+key */
			if (esc_timeout_tag != -1)
				g_source_remove(esc_timeout_tag);
			esc_timeout_tag = g_timeout_add(50, esc_timeout_callback, NULL);
			return TRUE;
		}
		return FALSE;
	} else if (mouse_state == 1) {
		if (key == '[') {
			/* Cancel timeout - might be mouse sequence or arrow keys */
			if (esc_timeout_tag != -1) {
				g_source_remove(esc_timeout_tag);
				esc_timeout_tag = -1;
			}
			mouse_state = 2;
			esc_pending = 0; /* clear pending since we'll handle this */
			return TRUE;
		}
		if (key == 'O') {
			/* This is ESC O - application mode arrow keys, re-emit immediately */
			if (esc_timeout_tag != -1) {
				g_source_remove(esc_timeout_tag);
				esc_timeout_tag = -1;
			}
			mouse_state = 3; /* special state for ESC O sequences */
			esc_pending = 0; /* clear pending since we'll handle this immediately */
			return TRUE;
		}
		/* Not SGR - cancel timeout and re-emit ESC */
		if (esc_timeout_tag != -1) {
			g_source_remove(esc_timeout_tag);
			esc_timeout_tag = -1;
		}
		mouse_state = 0;
		mouse_len = 0;
		if (esc_pending && !reemit_guard) {
			reemit_guard = 1;
			signal_emit("gui key pressed", 1, GINT_TO_POINTER(0x1b));
			reemit_guard = 0;
			esc_pending = 0;
		}
		return FALSE;
	} else if (mouse_state == 3) {
		/* ESC O sequence - re-emit ESC O and current key */
		mouse_state = 0;
		mouse_len = 0;
		esc_pending = 0;
		/* Cancel any pending timeout */
		if (esc_timeout_tag != -1) {
			g_source_remove(esc_timeout_tag);
			esc_timeout_tag = -1;
		}
		if (!reemit_guard) {
			reemit_guard = 1;
			signal_emit("gui key pressed", 1, GINT_TO_POINTER(0x1b));
			signal_emit("gui key pressed", 1, GINT_TO_POINTER('O'));
			signal_emit("gui key pressed", 1, GINT_TO_POINTER(key));
			reemit_guard = 0;
		}
		return TRUE;
	} else if (mouse_state >= 2) {
		if (mouse_len < (int) sizeof(mouse_buf) - 1)
			mouse_buf[mouse_len++] = (char) key;
		mouse_buf[mouse_len] = '\0';
		s = mouse_buf;
		/* Check if this is arrow keys (A/B/C/D) or other ESC sequences */
		if (mouse_len == 1 && (key == 'A' || key == 'B' || key == 'C' || key == 'D' ||
		                       key == 'H' || key == 'F' || key == '1' || key == '2' ||
		                       key == '3' || key == '4' || key == '5' || key == '6')) {
			/* This is arrow key or function key - re-emit ESC[ and current key */
			mouse_state = 0;
			mouse_len = 0;
			esc_pending = 0;
			if (esc_timeout_tag != -1) {
				g_source_remove(esc_timeout_tag);
				esc_timeout_tag = -1;
			}
			if (!reemit_guard) {
				reemit_guard = 1;
				signal_emit("gui key pressed", 1, GINT_TO_POINTER(0x1b));
				signal_emit("gui key pressed", 1, GINT_TO_POINTER('['));
				signal_emit("gui key pressed", 1, GINT_TO_POINTER(key));
				reemit_guard = 0;
			}
			return TRUE;
		}
		if (*s != '<') { /* not SGR mouse - cancel */
			mouse_state = 0;
			mouse_len = 0;
			esc_pending = 0;
			if (esc_timeout_tag != -1) {
				g_source_remove(esc_timeout_tag);
				esc_timeout_tag = -1;
			}
			return TRUE;
		}
		sc1 = strchr(s, ';');
		if (!sc1)
			return TRUE;
		sc2 = strchr(sc1 + 1, ';');
		if (!sc2)
			return TRUE;
		end = sc2 + 1;
		if (*end == '\0')
			return TRUE;
		last = end[(int) strlen(end) - 1];
		if (last != 'M' && last != 'm')
			return TRUE;
		braw = atoi(s + 1);
		x = atoi(sc1 + 1);
		y = atoi(sc2 + 1);
		x -= 1;
		y -= 1;
		press = (last == 'M');
		mouse_state = 0;
		mouse_len = 0;
		esc_pending = 0;
		/* Cancel timeout if still active */
		if (esc_timeout_tag != -1) {
			g_source_remove(esc_timeout_tag);
			esc_timeout_tag = -1;
		}
		if ((braw & 64) && press) {
			int dir;
			int delta;
			int px, py, pw, ph;
			dir = braw - 64;
			delta = (dir == 0 ? -3 : 3);
			for (mt = mainwindows; mt; mt = mt->next) {
				MAIN_WINDOW_REC *mw = mt->data;
				SP_MAINWIN_CTX *ctx = get_ctx(mw, FALSE);
				if (!ctx)
					continue;
				if (ctx->left_tw) {
					px = ctx->left_x;
					py = ctx->left_y;
					pw = ctx->left_w;
					ph = ctx->left_h;
					if (x >= px && x < px + pw && y >= py && y < py + ph) {
						ctx->left_scroll_offset =
						    MAX(0, ctx->left_scroll_offset + delta);
						redraw_one(mw);
						irssi_set_dirty();
						return TRUE;
					}
				}
				if (ctx->right_tw) {
					px = ctx->right_x;
					py = ctx->right_y;
					pw = ctx->right_w;
					ph = ctx->right_h;
					if (x >= px && x < px + pw && y >= py && y < py + ph) {
						ctx->right_scroll_offset =
						    MAX(0, ctx->right_scroll_offset + delta);
						redraw_one(mw);
						irssi_set_dirty();
						return TRUE;
					}
				}
			}
			return TRUE;
		}
		{
			int button;
			button = (braw & 3) + 1;
			if (press && button == 1) {
				/* consume click always */
				(void) handle_click_at(x, y, button);
				return TRUE;
			}
		}
		return TRUE;
	}
	return FALSE;
}

static void enable_mouse_tracking(void)
{
	fputs("\x1b[?1000h", stdout);
	fputs("\x1b[?1006h", stdout);
	fflush(stdout);
	mouse_tracking_enabled = TRUE;
}

static void disable_mouse_tracking(void)
{
	fputs("\x1b[?1006l", stdout);
	fputs("\x1b[?1000l", stdout);
	fflush(stdout);
	mouse_tracking_enabled = FALSE;
}

static void sig_irssi_init_finished(void)
{
	/* Force debug on to see what's happening */
	sp_debug = 1;
	/* Renumber windows to ensure proper order */
	renumber_windows_by_position();
	apply_reservations_all();
	apply_and_redraw();
}

void sidepanels_init(void)
{
	settings_add_bool("lookandfeel", "sidepanel_left", TRUE);
	settings_add_bool("lookandfeel", "sidepanel_right", TRUE);
	settings_add_int("lookandfeel", "sidepanel_left_width", 18);
	settings_add_int("lookandfeel", "sidepanel_right_width", 18);
	settings_add_bool("lookandfeel", "sidepanel_right_auto_hide", TRUE);

	settings_add_bool("lookandfeel", "sidepanel_debug", FALSE);
	sp_enable_mouse = TRUE; /* force native */
	read_settings();
	mw_to_ctx = g_hash_table_new(g_direct_hash, g_direct_equal);
	/* Apply reservations but don't redraw yet - wait for irssi init finished */
	apply_reservations_all();
	enable_mouse_tracking();
	esc_pending = 0;
	reemit_guard = 0;
	signal_add("irssi init finished", (SIGNAL_FUNC) sig_irssi_init_finished);
	signal_add("mainwindow created", (SIGNAL_FUNC) sig_mainwindow_created);
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
	signal_add("mainwindow resized", (SIGNAL_FUNC) sig_mainwindow_resized);
	signal_add("window changed", (SIGNAL_FUNC) sig_window_changed);
	signal_add("window item changed", (SIGNAL_FUNC) sig_window_item_changed);
	signal_add("window created", (SIGNAL_FUNC) sig_window_created);
	signal_add("window destroyed", (SIGNAL_FUNC) sig_window_destroyed);
	signal_add("window item new", (SIGNAL_FUNC) sig_window_item_new);
	signal_add("query created", (SIGNAL_FUNC) sig_query_created);
	signal_add("channel joined", (SIGNAL_FUNC) sig_channel_joined);
	signal_add("nicklist changed", (SIGNAL_FUNC) sig_nicklist_changed);
	signal_add("nicklist new", (SIGNAL_FUNC) sig_nicklist_new);
	signal_add("nicklist remove", (SIGNAL_FUNC) redraw_all);
	signal_add("nicklist gone changed", (SIGNAL_FUNC) redraw_all);
	signal_add("nicklist serverop changed", (SIGNAL_FUNC) redraw_all);
	signal_add("nicklist host changed", (SIGNAL_FUNC) redraw_all);
	signal_add("nicklist account changed", (SIGNAL_FUNC) redraw_all);
	/* Message events for live nicklist updates */
	signal_add("message join", (SIGNAL_FUNC) sig_message_join);
	signal_add("message part", (SIGNAL_FUNC) sig_message_part);
	signal_add("message quit", (SIGNAL_FUNC) sig_message_quit);
	signal_add("message kick", (SIGNAL_FUNC) redraw_all);
	signal_add("message nick", (SIGNAL_FUNC) sig_message_nick);
	signal_add("message own_nick", (SIGNAL_FUNC) redraw_all);
	/* Channel state changes */
	signal_add("channel created", (SIGNAL_FUNC) redraw_all);
	signal_add("channel destroyed", (SIGNAL_FUNC) redraw_all);
	signal_add("channel topic changed", (SIGNAL_FUNC) redraw_all);
	signal_add("channel sync", (SIGNAL_FUNC) redraw_all);
	signal_add("channel wholist", (SIGNAL_FUNC) redraw_all);
	/* Live activity notifications */
	signal_add("print text", (SIGNAL_FUNC) sig_print_text);
}

void sidepanels_deinit(void)
{
	GSList *tmp;
	signal_remove("irssi init finished", (SIGNAL_FUNC) sig_irssi_init_finished);
	signal_remove("mainwindow created", (SIGNAL_FUNC) sig_mainwindow_created);
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	signal_remove("mainwindow resized", (SIGNAL_FUNC) sig_mainwindow_resized);
	signal_remove("window changed", (SIGNAL_FUNC) sig_window_changed);
	signal_remove("window item changed", (SIGNAL_FUNC) sig_window_item_changed);
	signal_remove("window created", (SIGNAL_FUNC) sig_window_created);
	signal_remove("window destroyed", (SIGNAL_FUNC) sig_window_destroyed);
	signal_remove("window item new", (SIGNAL_FUNC) sig_window_item_new);
	signal_remove("query created", (SIGNAL_FUNC) sig_query_created);
	signal_remove("channel joined", (SIGNAL_FUNC) sig_channel_joined);
	signal_remove("nicklist changed", (SIGNAL_FUNC) sig_nicklist_changed);
	signal_remove("nicklist new", (SIGNAL_FUNC) sig_nicklist_new);
	signal_remove("nicklist remove", (SIGNAL_FUNC) redraw_all);
	signal_remove("nicklist gone changed", (SIGNAL_FUNC) redraw_all);
	signal_remove("nicklist serverop changed", (SIGNAL_FUNC) redraw_all);
	signal_remove("nicklist host changed", (SIGNAL_FUNC) redraw_all);
	signal_remove("nicklist account changed", (SIGNAL_FUNC) redraw_all);
	/* Message events for live nicklist updates */
	signal_remove("message join", (SIGNAL_FUNC) sig_message_join);
	signal_remove("message part", (SIGNAL_FUNC) sig_message_part);
	signal_remove("message quit", (SIGNAL_FUNC) sig_message_quit);
	signal_remove("message kick", (SIGNAL_FUNC) redraw_all);
	signal_remove("message nick", (SIGNAL_FUNC) sig_message_nick);
	signal_remove("message own_nick", (SIGNAL_FUNC) redraw_all);
	/* Channel state changes */
	signal_remove("channel created", (SIGNAL_FUNC) redraw_all);
	signal_remove("channel destroyed", (SIGNAL_FUNC) redraw_all);
	signal_remove("channel topic changed", (SIGNAL_FUNC) redraw_all);
	signal_remove("channel sync", (SIGNAL_FUNC) redraw_all);
	signal_remove("channel wholist", (SIGNAL_FUNC) redraw_all);
	/* Live activity notifications */
	signal_remove("print text", (SIGNAL_FUNC) sig_print_text);
	/* Remove reservations */
	for (tmp = mainwindows; tmp != NULL; tmp = tmp->next) {
		MAIN_WINDOW_REC *mw = tmp->data;
		destroy_ctx(mw);
		if (mw->statusbar_columns_left)
			mainwindow_set_statusbar_columns(mw, -mw->statusbar_columns_left, 0);
		if (mw->statusbar_columns_right)
			mainwindow_set_statusbar_columns(mw, 0, -mw->statusbar_columns_right);
	}
	if (mw_to_ctx) {
		g_hash_table_destroy(mw_to_ctx);
		mw_to_ctx = NULL;
	}
	if (window_priorities) {
		g_hash_table_destroy(window_priorities);
		window_priorities = NULL;
	}
	disable_mouse_tracking();
	/* Clean up timeout */
	if (esc_timeout_tag != -1) {
		g_source_remove(esc_timeout_tag);
		esc_timeout_tag = -1;
	}
	if (sp_log) {
		fclose(sp_log);
		sp_log = NULL;
	}
}