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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "term.h"
#include "terminfo-core.h"
#include "utf8.h"

#include <signal.h>

/* returns number of characters in the beginning of the buffer being a
   a single character, or -1 if more input is needed. The character will be
   saved in result */
typedef int (*TERM_INPUT_FUNC)(const unsigned char *buffer, int size,
			       unichar *result);

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
static int auto_detach;

static int last_fg, last_bg, last_attrs;

static int redraw_needed, redraw_tag;
static int freeze_counter;

static TERM_INPUT_FUNC input_func;
static unsigned char term_inbuf[256];
static int term_inbuf_pos;

/* SIGCONT handler */
static void sig_cont(int p)
{
        redraw_needed = TRUE;
	terminfo_cont(current_term);
}

static int redraw_timeout(void)
{
	if (redraw_needed) {
		irssi_redraw();
                redraw_needed = FALSE;
	}

        return 1;
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
        redraw_tag = g_timeout_add(500, (GSourceFunc) redraw_timeout, NULL);

	curs_x = curs_y = 0;
	term_width = current_term->width;
	term_height = current_term->height;
	root_window = term_window_create(0, 0, term_width, term_height);
        term_detached = FALSE;

        term_lines_empty = g_new0(char, term_height);

        term_set_input_type(TERM_TYPE_8BIT);
	term_common_init();
        g_atexit(term_deinit);
        return TRUE;
}

void term_deinit(void)
{
	if (current_term != NULL) {
		signal(SIGCONT, SIG_DFL);
		g_source_remove(redraw_tag);

		term_common_deinit();
		terminfo_core_deinit(current_term);
		current_term = NULL;
	}
}

static void term_move_real(void)
{
	if (term_detached) return;

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
		terminfo_resize(current_term);
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
        return current_term->has_colors;
}

/* Force the colors on any way you can */
void term_force_colors(int set)
{
	if (term_detached) return;

	terminfo_setup_colors(current_term, set);
}

/* Clear screen */
void term_clear(void)
{
	if (term_detached) return;

        term_set_color(root_window, ATTR_RESET);
	terminfo_clear();
        term_move_reset(0, 0);

	memset(term_lines_empty, 1, term_height);
}

/* Beep */
void term_beep(void)
{
	if (term_detached) return;

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

	if (term_detached) return;

        terminfo_set_normal();
        if (window->y == 0 && window->height == term_height) {
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

	if (term_detached) return;

	terminfo_scroll(window->y, window->y+window->height-1, count);
        term_move_reset(vcx, vcy);

        /* set the newly scrolled area dirty */
	for (y = 0; y < window->height; y++)
		term_lines_empty[window->y+y] = FALSE;
}

/* Change active color */
void term_set_color(TERM_WINDOW *window, int col)
{
	int set_normal;

	if (term_detached) return;

        set_normal = ((col & ATTR_RESETFG) && last_fg != -1) ||
		((col & ATTR_RESETBG) && last_bg != -1);
	if (((last_attrs & ATTR_BOLD) && (col & ATTR_BOLD) == 0) ||
	    ((last_attrs & ATTR_BLINK) && (col & ATTR_BLINK) == 0)) {
		/* we'll need to get rid of bold/blink - this can only be
		   done with setting the default color */
		set_normal = TRUE;
	}

	if (set_normal) {
		last_fg = last_bg = -1;
                last_attrs = 0;
		terminfo_set_normal();
	}

	if (!term_use_colors && (col & 0xf0) != 0)
		col |= ATTR_REVERSE;

	/* reversed text (use standout) */
	if (col & ATTR_REVERSE) {
		if ((last_attrs & ATTR_REVERSE) == 0)
			terminfo_set_standout(TRUE);
	} else if (last_attrs & ATTR_REVERSE)
		terminfo_set_standout(FALSE);

	/* set foreground color */
	if ((col & 0x0f) != last_fg &&
	    ((col & 0x0f) != 0 || (col & ATTR_RESETFG) == 0)) {
                if (term_use_colors) {
			last_fg = col & 0x0f;
			terminfo_set_fg(last_fg);
		}
	}

	/* set background color */
	if (col & ATTR_BLINK)
		col |= 0x80;
	else if (col & 0x80)
		col |= ATTR_BLINK;

	if ((col & 0xf0) >> 4 != last_bg &&
	    ((col & 0xf0) != 0 || (col & ATTR_RESETBG) == 0)) {
                if (term_use_colors) {
			last_bg = (col & 0xf0) >> 4;
			terminfo_set_bg(last_bg);
		}
	}

	/* bold */
	if (col & 0x08)
		col |= ATTR_BOLD;
	else if (col & ATTR_BOLD)
		terminfo_set_bold();

	/* underline */
	if (col & ATTR_UNDERLINE) {
		if ((last_attrs & ATTR_UNDERLINE) == 0)
			terminfo_set_uline(TRUE);
	} else if (last_attrs & ATTR_UNDERLINE)
		terminfo_set_uline(FALSE);

        last_attrs = col & ~0xff;
}

void term_move(TERM_WINDOW *window, int x, int y)
{
	vcmove = TRUE;
	vcx = x+window->x;
        vcy = y+window->y;

	if (vcx >= term_width)
		vcx = term_width-1;
	if (vcy >= term_height)
                vcy = term_height-1;
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

void term_addch(TERM_WINDOW *window, int chr)
{
	if (term_detached) return;

	if (vcmove) term_move_real();

	if (vcy < term_height-1 || vcx < term_width-1) {
		/* With UTF-8, move cursor only if this char is either
		   single-byte (8. bit off) or beginning of multibyte
		   (7. bit off) */
		if (term_type != TERM_TYPE_UTF8 ||
		    (chr & 0x80) == 0 || (chr & 0x40) == 0) {
			term_printed_text(1);
		}

		putc(chr, window->term->out);
	}
}

static void term_addch_utf8(TERM_WINDOW *window, unichar chr)
{
	char buf[10];
	int i, len;

	len = utf16_char_to_utf8(chr, buf);
	for (i = 0;  i < len; i++)
                putc(buf[i], window->term->out);
}

void term_add_unichar(TERM_WINDOW *window, unichar chr)
{
	if (term_detached) return;

	if (vcmove) term_move_real();
	if (vcy == term_height-1 && vcx == term_width-1)
		return; /* last char in screen */

	switch (term_type) {
	case TERM_TYPE_UTF8:
	  	term_printed_text(utf8_width(chr));
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

void term_addstr(TERM_WINDOW *window, const char *str)
{
	int len;

	if (term_detached) return;

	if (vcmove) term_move_real();
	len = strlen(str); /* FIXME utf8 or big5 */
        term_printed_text(len);

	if (vcy != term_height || vcx != 0)
		fputs(str, window->term->out);
	else
		fwrite(str, 1, len-1, window->term->out);
}

void term_clrtoeol(TERM_WINDOW *window)
{
	if (term_detached) return;

	/* clrtoeol() doesn't necessarily understand colors */
	if (last_fg == -1 && last_bg == -1 &&
	    (last_attrs & (ATTR_UNDERLINE|ATTR_REVERSE)) == 0) {
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

void term_move_cursor(int x, int y)
{
	curs_x = x;
        curs_y = y;
}

void term_refresh(TERM_WINDOW *window)
{
	if (term_detached || freeze_counter > 0)
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

void term_auto_detach(int set)
{
        auto_detach = set;
}

void term_detach(void)
{
	terminfo_stop(current_term);

        fclose(current_term->in);
        fclose(current_term->out);

	current_term->in = NULL;
	current_term->out = NULL;
        term_detached = TRUE;
}

void term_attach(FILE *in, FILE *out)
{
	current_term->in = in;
	current_term->out = out;
        term_detached = FALSE;

	terminfo_cont(current_term);
	irssi_redraw();
}

void term_stop(void)
{
	if (term_detached) {
		kill(getpid(), SIGTSTP);
	} else {
		terminfo_stop(current_term);
		kill(getpid(), SIGTSTP);
		terminfo_cont(current_term);
		irssi_redraw();
	}
}

static int input_utf8(const unsigned char *buffer, int size, unichar *result)
{
        const unsigned char *end = buffer;

	switch (get_utf8_char(&end, size, result)) {
	case -2:
		/* not UTF8 - fallback to 8bit ascii */
		*result = *buffer;
		return 1;
	case -1:
                /* need more data */
		return -1;
	default:
		return (int) (end-buffer)+1;
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

int term_gets(unichar *buffer, int size)
{
	int ret, i, char_len;

	if (term_detached)
		return 0;

        /* fread() doesn't work */
	if (size > sizeof(term_inbuf)-term_inbuf_pos)
		size = sizeof(term_inbuf)-term_inbuf_pos;

	ret = read(fileno(current_term->in),
		   term_inbuf + term_inbuf_pos, size);
	if (ret == 0) {
		/* EOF - terminal got lost */
		if (auto_detach)
                        term_detach();
		ret = -1;
	} else if (ret == -1 && (errno == EINTR || errno == EAGAIN))
		ret = 0;

	if (ret > 0) {
                /* convert input to unichars. */
		term_inbuf_pos += ret;
                ret = 0;
		for (i = 0; i < term_inbuf_pos; ) {
			char_len = input_func(term_inbuf+i, term_inbuf_pos-i,
					      buffer);
			if (char_len < 0)
				break;

			i += char_len;
                        buffer++;
                        ret++;
		}

		if (i >= term_inbuf_pos)
			term_inbuf_pos = 0;
		else if (i > 0) {
			memmove(term_inbuf, term_inbuf+i, term_inbuf_pos-i);
                        term_inbuf_pos -= i;
		}
	}

	return ret;
}
