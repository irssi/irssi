/*
 term-terminfo.c : irssi

    Copyright (C) 2001 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/fe-text/term.h>
#include <irssi/src/fe-text/terminfo-core.h>
#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-text/gui-printtext.h>
#include <irssi/src/core/utf8.h>

#include <signal.h>
#include <termios.h>
#include <stdio.h>

#ifdef HAVE_TERM_H
#ifdef NEED_CURSES_H
#include <curses.h>
#endif
#include <term.h>
#else
/* TODO: This needs arguments, starting with C2X. */
int tputs();
#endif

/* returns number of characters in the beginning of the buffer being a
   a single character, or -1 if more input is needed. The character will be
   saved in result */
typedef int (*TERM_INPUT_FUNC)(const unsigned char *buffer, int size, unichar *result);

struct _TERM_WINDOW {
	/* Terminal to use for window */
	TERM_REC *term;

	/* Area for window in terminal */
	int x, y;
	int width, height;
};

TERM_WINDOW *root_window;

static char *term_lines_empty; /* 1 if line is entirely empty */
static int vcmove, vcx, vcy, curs_visible;
static int crealx, crealy, cforcemove;
static int curs_x, curs_y;

static unsigned int last_fg, last_bg;
static int last_attrs;

static GSource *sigcont_source;
static volatile sig_atomic_t got_sigcont;
static int freeze_counter;

static TERM_INPUT_FUNC input_func;
static unsigned char term_inbuf[256];
static int term_inbuf_pos;

/* SIGCONT handler */
static void sig_cont(int p)
{
        got_sigcont = TRUE;
}

/* SIGCONT GSource */
static gboolean sigcont_prepare(GSource *source, gint *timeout)
{
	*timeout = -1;
	return got_sigcont;
}

static gboolean sigcont_check(GSource *source)
{
	return got_sigcont;
}

static gboolean sigcont_dispatch(GSource *source, GSourceFunc callback, gpointer user_data)
{
	got_sigcont = FALSE;
	if (callback == NULL)
		return TRUE;
	return callback(user_data);
}

static gboolean do_redraw(gpointer unused)
{
	terminfo_cont(current_term);
	irssi_redraw();

        return 1;
}

static GSourceFuncs sigcont_funcs = {
	.prepare = sigcont_prepare,
	.check = sigcont_check,
	.dispatch = sigcont_dispatch
};

static void term_atexit(void)
{
	if (!quitting && current_term && current_term->TI_rmcup) {
		/* Unexpected exit, avoid switching out of alternate screen
		   to keep any on-screen errors (like noperl_die()'s) */
		current_term->TI_rmcup = NULL;
	}

	term_deinit();
}

int term_init(void)
{
	struct sigaction act;
        int width, height;

	last_fg = last_bg = -1;
	last_attrs = 0;
	vcx = vcy = 0; crealx = crealy = -1;
	vcmove = FALSE; cforcemove = TRUE;
        curs_visible = TRUE;

	current_term = terminfo_core_init(stdin, stdout);
	if (current_term == NULL)
		return FALSE;

	if (term_get_size(&width, &height)) {
                current_term->width = width;
                current_term->height = height;
	}

        /* grab CONT signal */
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = sig_cont;
	sigaction(SIGCONT, &act, NULL);
	sigcont_source = g_source_new(&sigcont_funcs, sizeof(GSource));
	g_source_set_callback(sigcont_source, do_redraw, NULL, NULL);
	g_source_attach(sigcont_source, NULL);

	curs_x = curs_y = 0;
	term_width = current_term->width;
	term_height = current_term->height;
	root_window = term_window_create(0, 0, term_width, term_height);

        term_lines_empty = g_new0(char, term_height);

        term_set_input_type(TERM_TYPE_8BIT);
	term_common_init();
	atexit(term_atexit);
        return TRUE;
}

void term_deinit(void)
{
	if (current_term != NULL) {
		signal(SIGCONT, SIG_DFL);
		g_source_destroy(sigcont_source);
		g_source_unref(sigcont_source);

		term_common_deinit();
		terminfo_core_deinit(current_term);
		current_term = NULL;
	}
}

static void term_move_real(void)
{
	if (vcx != crealx || vcy != crealy || cforcemove) {
		if (curs_visible) {
			terminfo_set_cursor_visible(FALSE);
			curs_visible = FALSE;
		}

		if (cforcemove) {
			crealx = crealy = -1;
			cforcemove = FALSE;
		}
		terminfo_move_relative(crealx, crealy, vcx, vcy);
                crealx = vcx; crealy = vcy;
	}

        vcmove = FALSE;
}

/* Cursor position is unknown - move it immediately to known position */
static void term_move_reset(int x, int y)
{
	if (x >= term_width) x = term_width-1;
	if (y >= term_height) y = term_height-1;

	vcx = x; vcy = y;
        cforcemove = TRUE;
        term_move_real();
}

/* Resize terminal - if width or height is negative,
   the new size is unknown and should be figured out somehow */
void term_resize(int width, int height)
{
	if (width < 0 || height < 0) {
		width = current_term->width;
                height = current_term->height;
	}

	if (term_width != width || term_height != height) {
		term_width = current_term->width = width;
		term_height = current_term->height = height;
		term_window_move(root_window, 0, 0, term_width, term_height);

                g_free(term_lines_empty);
		term_lines_empty = g_new0(char, term_height);
	}

        term_move_reset(0, 0);
}

void term_resize_final(int width, int height)
{
}

/* Returns TRUE if terminal has colors */
int term_has_colors(void)
{
        return current_term->TI_colors > 0;
}

/* Force the colors on any way you can */
void term_force_colors(int set)
{
	terminfo_setup_colors(current_term, set);
}

/* Clear screen */
void term_clear(void)
{
        term_set_color(root_window, ATTR_RESET);
	terminfo_clear();
        term_move_reset(0, 0);

	memset(term_lines_empty, 1, term_height);
}

/* Beep */
void term_beep(void)
{
        terminfo_beep(current_term);
}

/* Create a new window in terminal */
TERM_WINDOW *term_window_create(int x, int y, int width, int height)
{
	TERM_WINDOW *window;

	window = g_new0(TERM_WINDOW, 1);
        window->term = current_term;
	window->x = x; window->y = y;
	window->width = width; window->height = height;
        return window;
}

/* Destroy a terminal window */
void term_window_destroy(TERM_WINDOW *window)
{
        g_free(window);
}

/* Move/resize a window */
void term_window_move(TERM_WINDOW *window, int x, int y,
		      int width, int height)
{
	window->x = x;
	window->y = y;
	window->width = width;
        window->height = height;
}

/* Clear window */
void term_window_clear(TERM_WINDOW *window)
{
	int y;

	terminfo_set_normal();
	if (window->y == 0 && window->height == term_height && window->width == term_width) {
		term_clear();
	} else {
		for (y = 0; y < window->height; y++) {
			term_move(window, 0, y);
			term_clrtoeol(window);
		}
	}
}

/* Scroll window up/down */
void term_window_scroll(TERM_WINDOW *window, int count)
{
	int y;

	terminfo_scroll(window->y, window->y+window->height-1, count);
        term_move_reset(vcx, vcy);

        /* set the newly scrolled area dirty */
	for (y = 0; (window->y+y) < term_height && y < window->height; y++)
		term_lines_empty[window->y+y] = FALSE;
}

#ifdef TPUTS_SVR4
#define putc_arg_t char
#else
#define putc_arg_t int
#endif
inline static int term_putchar(putc_arg_t c)
{
        return fputc(c, current_term->out);
}

static int termctl_set_color_24bit(int bg, unsigned int lc)
{
	static char buf[20];
	const unsigned char color[] = { lc >> 16, lc >> 8, lc };

	if (!term_use_colors24) {
		if (bg)
			terminfo_set_bg(color_24bit_256(color));
		else
			terminfo_set_fg(color_24bit_256(color));
		return -1;
	}

	/* \e[x8;2;...;...;...m */
	sprintf(buf, "\033[%d8;2;%d;%d;%dm", bg ? 4 : 3, color[0], color[1], color[2]);
	return tputs(buf, 0, term_putchar);
}

#define COLOR_RESET UINT_MAX
#define COLOR_BLACK24 COLOR_RESET - 1

/* Change active color */
void term_set_color2(TERM_WINDOW *window, int col, unsigned int fgcol24, unsigned int bgcol24)
{
	int set_normal;

	unsigned int fg, bg;
	if (col & ATTR_FGCOLOR24) {
		if (fgcol24)
			fg = fgcol24 << 8;
		else
			fg = COLOR_BLACK24;
	} else
		fg = (col & FG_MASK);

	if (col & ATTR_BGCOLOR24) {
		if (bgcol24)
			bg = bgcol24 << 8;
		else
			bg = COLOR_BLACK24;
	} else
		bg = ((col & BG_MASK) >> BG_SHIFT);

	if (!term_use_colors && bg > 0)
		col |= ATTR_REVERSE;

	set_normal = ((col & ATTR_RESETFG) && last_fg != COLOR_RESET) ||
	             ((col & ATTR_RESETBG) && last_bg != COLOR_RESET);
	if (((last_attrs & ATTR_BOLD) && (col & ATTR_BOLD) == 0) ||
	    ((last_attrs & ATTR_REVERSE) && (col & ATTR_REVERSE) == 0) ||
	    ((last_attrs & ATTR_BLINK) && (col & ATTR_BLINK) == 0)) {
		/* we'll need to get rid of bold/blink/reverse - this
		   can only be done with setting the default color */
		set_normal = TRUE;
	}

	if (set_normal) {
		last_fg = last_bg = COLOR_RESET;
		last_attrs = 0;
		terminfo_set_normal();
	}

	/* set foreground color */
	if (fg != last_fg && (fg != 0 || (col & ATTR_RESETFG) == 0)) {
		if (term_use_colors) {
			last_fg = fg;
			if (fg >> 8)
				termctl_set_color_24bit(0, last_fg == COLOR_BLACK24 ? 0 :
				                                                      last_fg >> 8);
			else
				terminfo_set_fg(last_fg);
		}
	}

	/* set background color */
	if (window && window->term->TI_colors &&
	    (term_color256map[bg & 0xff] & 8) == window->term->TI_colors)
		col |= ATTR_BLINK;
	if (col & ATTR_BLINK)
		current_term->tr_set_blink(current_term);

	if (bg != last_bg && (bg != 0 || (col & ATTR_RESETBG) == 0)) {
		if (term_use_colors) {
			last_bg = bg;
			if (bg >> 8)
				termctl_set_color_24bit(1, last_bg == COLOR_BLACK24 ? 0 :
				                                                      last_bg >> 8);
			else
				terminfo_set_bg(last_bg);
		}
	}

	/* reversed text */
	if (col & ATTR_REVERSE)
		terminfo_set_reverse();

	/* bold */
	if (window && window->term->TI_colors &&
	    (term_color256map[fg & 0xff] & 8) == window->term->TI_colors)
		col |= ATTR_BOLD;
	if (col & ATTR_BOLD)
		terminfo_set_bold();

	/* underline */
	if (col & ATTR_UNDERLINE) {
		if ((last_attrs & ATTR_UNDERLINE) == 0)
			terminfo_set_uline(TRUE);
	} else if (last_attrs & ATTR_UNDERLINE)
		terminfo_set_uline(FALSE);

	/* italic */
	if (col & ATTR_ITALIC) {
		if ((last_attrs & ATTR_ITALIC) == 0)
			terminfo_set_italic(TRUE);
	} else if (last_attrs & ATTR_ITALIC)
		terminfo_set_italic(FALSE);

	/* update the new attribute settings whilst ignoring color values.  */
	last_attrs = col & ~(BG_MASK | FG_MASK);
}

void term_move(TERM_WINDOW *window, int x, int y)
{
	if (x >= 0 && y >= 0) {
		vcmove = TRUE;
		vcx = x+window->x;
		vcy = y+window->y;

		if (vcx >= term_width)
			vcx = term_width-1;
		if (vcy >= term_height)
			vcy = term_height-1;
	}
}

static void term_printed_text(int count)
{
	term_lines_empty[vcy] = FALSE;

	/* if we continued writing past the line, wrap to next line.
	   However, next term_move() really shouldn't try to cache
	   the move, otherwise terminals would try to combine the
	   last word in upper line with first word in lower line. */
	vcx += count;
	while (vcx >= term_width) {
		vcx -= term_width;
		if (vcy < term_height-1) vcy++;
		if (vcx > 0) term_lines_empty[vcy] = FALSE;
	}

	crealx += count;
	if (crealx >= term_width)
		cforcemove = TRUE;
}

void term_addch(TERM_WINDOW *window, char chr)
{
	if (vcmove) term_move_real();

	/* With UTF-8, move cursor only if this char is either
	   single-byte (8. bit off) or beginning of multibyte
	   (7. bit off) */
	if (term_type != TERM_TYPE_UTF8 ||
	    (chr & 0x80) == 0 || (chr & 0x40) == 0) {
		term_printed_text(1);
	}

	putc(chr, window->term->out);
}

static void term_addch_utf8(TERM_WINDOW *window, unichar chr)
{
	char buf[10];
	int i, len;

	len = g_unichar_to_utf8(chr, buf);
	for (i = 0;  i < len; i++)
                putc(buf[i], window->term->out);
}

void term_add_unichar(TERM_WINDOW *window, unichar chr)
{
	if (vcmove) term_move_real();

	switch (term_type) {
	case TERM_TYPE_UTF8:
		term_printed_text(unichar_isprint(chr) ? i_wcwidth(chr) : 1);
                term_addch_utf8(window, chr);
		break;
	case TERM_TYPE_BIG5:
		if (chr > 0xff) {
			term_printed_text(2);
			putc((chr >> 8) & 0xff, window->term->out);
		} else {
			term_printed_text(1);
		}
		putc((chr & 0xff), window->term->out);
                break;
	default:
		term_printed_text(1);
		putc(chr, window->term->out);
                break;
	}
}

int term_addstr(TERM_WINDOW *window, const char *str)
{
	int len, raw_len;
	unichar tmp;
	const char *ptr;

	if (vcmove) term_move_real();

	len = 0;
	raw_len = strlen(str);

	/* The string length depends on the terminal encoding */

	ptr = str;

	if (term_type == TERM_TYPE_UTF8) {
		while (*ptr != '\0') {
			tmp = g_utf8_get_char_validated(ptr, -1);
			/* On utf8 error, treat as single byte and try to
			   continue interpreting rest of string as utf8 */
			if (tmp == (gunichar)-1 || tmp == (gunichar)-2) {
				len++;
				ptr++;
			} else {
				len += unichar_isprint(tmp) ? i_wcwidth(tmp) : 1;
				ptr = g_utf8_next_char(ptr);
			}
		}
	} else
		len = raw_len;

        term_printed_text(len);

	/* Use strlen() here since we need the number of raw bytes */
	fwrite(str, 1, raw_len, window->term->out);

	return len;
}

void term_clrtoeol(TERM_WINDOW *window)
{
	if (vcx < window->x) {
		/* we just wrapped outside of the split, warp the cursor back into the window */
		vcx += window->x;
		vcmove = TRUE;
	}
	if (window->x + window->width < term_width) {
		/* we need to fill a vertical split */
		if (vcmove) term_move_real();
		terminfo_repeat(' ', window->x + window->width - vcx + 1);
		terminfo_move(vcx, vcy);
		term_lines_empty[vcy] = FALSE;
	} else {
		/* clrtoeol() doesn't necessarily understand colors */
		if (last_fg == -1 && last_bg == -1 &&
		    (last_attrs & (ATTR_UNDERLINE|ATTR_REVERSE|ATTR_ITALIC)) == 0) {
			if (!term_lines_empty[vcy]) {
				if (vcmove) term_move_real();
				terminfo_clrtoeol();
				if (vcx == 0) term_lines_empty[vcy] = TRUE;
			}
		} else if (vcx < term_width) {
			/* we'll need to fill the line ourself. */
			if (vcmove) term_move_real();
			terminfo_repeat(' ', term_width-vcx);
			terminfo_move(vcx, vcy);
			term_lines_empty[vcy] = FALSE;
		}
	}
}

void term_window_clrtoeol(TERM_WINDOW* window, int ypos)
{
	if (ypos >= 0 && window->y + ypos != vcy) {
		/* the line is already full */
		return;
	}
	term_clrtoeol(window);
	if (window->x + window->width < term_width) {
		gui_printtext_window_border(window->x + window->width, window->y + ypos);
		term_set_color(window, ATTR_RESET);
	}
}

void term_window_clrtoeol_abs(TERM_WINDOW* window, int ypos)
{
	term_window_clrtoeol(window, ypos - window->y);
}

void term_move_cursor(int x, int y)
{
	curs_x = x;
        curs_y = y;
}

void term_refresh(TERM_WINDOW *window)
{
	if (freeze_counter > 0)
		return;

	term_move(root_window, curs_x, curs_y);
	term_move_real();

	if (!curs_visible) {
		terminfo_set_cursor_visible(TRUE);
                curs_visible = TRUE;
	}

	term_set_color(window, ATTR_RESET);
	fflush(window != NULL ? window->term->out : current_term->out);
}

void term_refresh_freeze(void)
{
        freeze_counter++;
}

void term_refresh_thaw(void)
{
	if (--freeze_counter == 0)
                term_refresh(NULL);
}

void term_stop(void)
{
	terminfo_stop(current_term);
	kill(getpid(), SIGTSTP);
	/* this call needs to stay here in case the TSTP was ignored,
	   because then we never see a CONT to call the restoration
	   code. On the other hand we also cannot remove the CONT
	   handler because then nothing would restore the screen when
	   Irssi is killed with TSTP/STOP from external. */
	terminfo_cont(current_term);
	irssi_redraw();
}

static int input_utf8(const unsigned char *buffer, int size, unichar *result)
{
	unichar c = g_utf8_get_char_validated((char *) buffer, size);

	/* GLib >= 2.63 do not accept Unicode NUL anymore */
	if (c == (unichar) -2 && *buffer == 0 && size > 0)
		c = 0;

	switch (c) {
	case (unichar)-1:
		/* not UTF8 - fallback to 8bit ascii */
		*result = *buffer;
		return 1;
	case (unichar)-2:
                /* need more data */
		return -1;
	default:
		*result = c;
		return g_utf8_skip[*buffer];
	}
}

static int input_big5(const unsigned char *buffer, int size, unichar *result)
{
	if (is_big5_hi(*buffer)) {
		/* could be */
		if (size == 1)
			return -1;

		if (is_big5_los(buffer[1]) || is_big5_lox(buffer[1])) {
                        *result = buffer[1] + ((int) *buffer << 8);
			return 2;
		}
	}

        *result = *buffer;
	return 1;
}

static int input_8bit(const unsigned char *buffer, int size, unichar *result)
{
        *result = *buffer;
        return 1;
}

void term_set_input_type(int type)
{
	switch (type) {
	case TERM_TYPE_UTF8:
                input_func = input_utf8;
                break;
	case TERM_TYPE_BIG5:
                input_func = input_big5;
		break;
	default:
                input_func = input_8bit;
	}
}

void term_gets(GArray *buffer, int *line_count)
{
	int ret, i, char_len;

        /* fread() doesn't work */

	ret = read(fileno(current_term->in),
		   term_inbuf + term_inbuf_pos, sizeof(term_inbuf)-term_inbuf_pos);
	if (ret == 0) {
		/* EOF - terminal got lost */
		ret = -1;
	} else if (ret == -1 && (errno == EINTR || errno == EAGAIN))
		ret = 0;
	if (ret == -1)
		signal_emit("command quit", 1, "Lost terminal");

	if (ret > 0) {
                /* convert input to unichars. */
		term_inbuf_pos += ret;
		for (i = 0; i < term_inbuf_pos; ) {
			unichar key;
			char_len = input_func(term_inbuf+i, term_inbuf_pos-i,
					      &key);
			if (char_len < 0)
				break;
			g_array_append_val(buffer, key);
			if (key == '\r' || key == '\n')
				(*line_count)++;

			i += char_len;
		}

		if (i >= term_inbuf_pos)
			term_inbuf_pos = 0;
		else if (i > 0) {
			memmove(term_inbuf, term_inbuf+i, term_inbuf_pos-i);
                        term_inbuf_pos -= i;
		}
	}
}

static const char* term_env_warning =
	"You seem to be running Irssi inside %2$s, but the TERM environment variable "
	"is set to '%1$s', which can cause display glitches.\n"
	"Consider changing TERM to '%2$s' or '%2$s-256color' instead.";

void term_environment_check(void)
{
	const char *term, *sty, *tmux, *multiplexer;

	term = g_getenv("TERM");
	sty = g_getenv("STY");
	tmux = g_getenv("TMUX");

	multiplexer = (sty && *sty) ? "screen" :
	              (tmux && *tmux) ? "tmux" : NULL;

	if (!multiplexer) {
		return;
	}

	if (term && (g_str_has_prefix(term, "screen") ||
	             g_str_has_prefix(term, "tmux"))) {
		return;
	}

	g_warning(term_env_warning, term, multiplexer);
}
