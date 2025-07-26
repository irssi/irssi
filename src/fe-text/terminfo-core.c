#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/fe-text/terminfo-core.h>

#ifndef _POSIX_VDISABLE
#  define _POSIX_VDISABLE 0
#endif

#ifdef TPUTS_SVR4
#define putc_arg_t char
#else
#define putc_arg_t int
#endif
#define tput(s) tputs(s, 0, term_putchar)
inline static int term_putchar(putc_arg_t c)
{
        return fputc(c, current_term->out);
}

#ifdef HAVE_TERM_H
#ifdef NEED_CURSES_H
#include <curses.h>
#endif
#include <term.h>
#else
/* Don't bother including curses.h because of these -
   they might not even be defined there */
char *tparm();
int tputs();

int setupterm();
char *tigetstr();
int tigetnum();
int tigetflag();
#endif

#define term_getstr(x, buffer) tigetstr(x.ti_name)
#define term_getnum(x) tigetnum(x.ti_name);
#define term_getflag(x) tigetflag(x.ti_name);

#define CAP_TYPE_FLAG	0
#define CAP_TYPE_INT	1
#define CAP_TYPE_STR	2

typedef struct {
	char *ti_name; /* terminfo name */
	char *tc_name; /* termcap name */
	int type;
	unsigned int offset;
} TERMINFO_REC;

TERM_REC *current_term;

/* Define only what we might need */
static TERMINFO_REC tcaps[] = {
	/* Terminal size */
	{ "cols",   "co",  CAP_TYPE_INT,  G_STRUCT_OFFSET(TERM_REC, width) },
	{ "lines",  "li",  CAP_TYPE_INT,  G_STRUCT_OFFSET(TERM_REC, height) },

	/* Cursor movement */
	{ "smcup",  "ti",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_smcup) },
	{ "rmcup",  "te",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_rmcup) },
	{ "cup",    "cm",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_cup) },
	{ "hpa",    "ch",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_hpa) },
	{ "vpa",    "vh",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_vpa) },
	{ "cub1",   "le",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_cub1) },
	{ "cuf1",   "nd",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_cuf1) },
	{ "civis",  "vi",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_civis) },
	{ "cnorm",  "ve",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_cnorm) },

	/* Scrolling */
	{ "csr",    "cs",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_csr) },
	{ "wind",   "wi",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_wind) },
	{ "ri",     "sr",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_ri) },
	{ "rin",    "SR",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_rin) },
	{ "ind",    "sf",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_ind) },
	{ "indn",   "SF",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_indn) },
	{ "il",     "AL",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_il) },
	{ "il1",    "al",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_il1) },
	{ "dl",     "DL",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_dl) },
	{ "dl1",    "dl",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_dl1) },

	/* Clearing screen */
	{ "clear",  "cl",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_clear) },
	{ "ed",     "cd",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_ed) },

	/* Clearing to end of line */
	{ "el",     "ce",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_el) },

	/* Repeating character */
	{ "rep",    "rp",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_rep) },

	/* Colors */
	{ "colors", "Co",   CAP_TYPE_INT,   G_STRUCT_OFFSET(TERM_REC, TI_colors) },
	{ "sgr0",   "me",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_sgr0) },
	{ "smul",   "us",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_smul) },
	{ "rmul",   "ue",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_rmul) },
	{ "smso",   "so",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_smso) },
	{ "rmso",   "se",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_rmso) },
	{ "sitm",   "ZH",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_sitm) },
	{ "ritm",   "ZR",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_ritm) },
	{ "bold",   "md",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_bold) },
	{ "blink",  "mb",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_blink) },
	{ "rev",    "mr",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_rev) },
	{ "setaf",  "AF",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_setaf) },
	{ "setab",  "AB",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_setab) },
	{ "setf",   "Sf",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_setf) },
	{ "setb",   "Sb",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_setb) },

	/* Beep */
	{ "bel",    "bl",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_bel) },

	/* Keyboard-transmit mode */
	{ "smkx",   "ks",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_smkx) },
	{ "rmkx",   "ke",  CAP_TYPE_STR,  G_STRUCT_OFFSET(TERM_REC, TI_rmkx) },
};

/* Move cursor (cursor_address / cup) */
static void _move_cup(TERM_REC *term, int x, int y)
{
	tput(tparm(term->TI_cup, y, x, 0, 0, 0, 0, 0, 0, 0));
}

/* Move cursor (column_address+row_address / hpa+vpa) */
static void _move_pa(TERM_REC *term, int x, int y)
{
	tput(tparm(term->TI_hpa, x, 0, 0, 0, 0, 0, 0, 0, 0));
	tput(tparm(term->TI_vpa, y, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Move cursor from a known position */
static void _move_relative(TERM_REC *term, int oldx, int oldy, int x, int y)
{
	if (oldx == 0 && x == 0 && y == oldy+1) {
		/* move to beginning of next line -
		   hope this works everywhere */
		tput("\r\n");
                return;
	}

	if (oldx > 0 && y == oldy) {
                /* move cursor left/right */
		if (x == oldx-1 && term->TI_cub1) {
			tput(tparm(term->TI_cub1, 0, 0, 0, 0, 0, 0, 0, 0, 0));
			return;
		}
		if (x == oldx+1 && y == oldy && term->TI_cuf1) {
			tput(tparm(term->TI_cuf1, 0, 0, 0, 0, 0, 0, 0, 0, 0));
			return;
		}
	}

        /* fallback to absolute positioning */
	if (term->TI_cup) {
		tput(tparm(term->TI_cup, y, x, 0, 0, 0, 0, 0, 0, 0));
		return;
	}

	if (oldy != y)
		tput(tparm(term->TI_vpa, y, 0, 0, 0, 0, 0, 0, 0, 0));
	if (oldx != x)
		tput(tparm(term->TI_hpa, x, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Set cursor visible/invisible */
static void _set_cursor_visible(TERM_REC *term, int set)
{
	tput(tparm(set ? term->TI_cnorm : term->TI_civis, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

#define scroll_region_setup(term, y1, y2)                                                          \
	if ((term)->TI_csr != NULL)                                                                \
		tput(tparm((term)->TI_csr, y1, y2, 0, 0, 0, 0, 0, 0, 0));                          \
	else if ((term)->TI_wind != NULL)                                                          \
		tput(tparm((term)->TI_wind, y1, y2, 0, (term)->width - 1, 0, 0, 0, 0, 0));

/* Scroll (change_scroll_region+parm_rindex+parm_index / csr+rin+indn) */
static void _scroll_region(TERM_REC *term, int y1, int y2, int count)
{
	/* setup the scrolling region to wanted area */
	scroll_region_setup(term, y1, y2);

	term->tr_move(term, 0, y1);
	if (count > 0) {
		term->tr_move(term, 0, y2);
		tput(tparm(term->TI_indn, count, count, 0, 0, 0, 0, 0, 0, 0));
	} else if (count < 0) {
		term->tr_move(term, 0, y1);
		tput(tparm(term->TI_rin, -count, -count, 0, 0, 0, 0, 0, 0, 0));
	}

	/* reset the scrolling region to full screen */
	scroll_region_setup(term, 0, term->height - 1);
}

/* Scroll (change_scroll_region+scroll_reverse+scroll_forward / csr+ri+ind) */
static void _scroll_region_1(TERM_REC *term, int y1, int y2, int count)
{
	int i;

	/* setup the scrolling region to wanted area */
	scroll_region_setup(term, y1, y2);

	if (count > 0) {
		term->tr_move(term, 0, y2);
		for (i = 0; i < count; i++)
			tput(tparm(term->TI_ind, 0, 0, 0, 0, 0, 0, 0, 0, 0));
	} else if (count < 0) {
		term->tr_move(term, 0, y1);
		for (i = count; i < 0; i++)
			tput(tparm(term->TI_ri, 0, 0, 0, 0, 0, 0, 0, 0, 0));
	}

	/* reset the scrolling region to full screen */
	scroll_region_setup(term, 0, term->height - 1);
}

/* Scroll (parm_insert_line+parm_delete_line / il+dl) */
static void _scroll_line(TERM_REC *term, int y1, int y2, int count)
{
	/* setup the scrolling region to wanted area -
	   this might not necessarily work with il/dl, but at least it
	   looks better if it does */
	scroll_region_setup(term, y1, y2);

	if (count > 0) {
		term->tr_move(term, 0, y1);
		tput(tparm(term->TI_dl, count, count, 0, 0, 0, 0, 0, 0, 0));
		term->tr_move(term, 0, y2 - count + 1);
		tput(tparm(term->TI_il, count, count, 0, 0, 0, 0, 0, 0, 0));
	} else if (count < 0) {
		term->tr_move(term, 0, y2 + count + 1);
		tput(tparm(term->TI_dl, -count, -count, 0, 0, 0, 0, 0, 0, 0));
		term->tr_move(term, 0, y1);
		tput(tparm(term->TI_il, -count, -count, 0, 0, 0, 0, 0, 0, 0));
	}

	/* reset the scrolling region to full screen */
	scroll_region_setup(term, 0, term->height - 1);
}

/* Scroll (insert_line+delete_line / il1+dl1) */
static void _scroll_line_1(TERM_REC *term, int y1, int y2, int count)
{
	int i;

	if (count > 0) {
		term->tr_move(term, 0, y1);
		for (i = 0; i < count; i++)
			tput(tparm(term->TI_dl1, 0, 0, 0, 0, 0, 0, 0, 0, 0));
		term->tr_move(term, 0, y2 - count + 1);
		for (i = 0; i < count; i++)
			tput(tparm(term->TI_il1, 0, 0, 0, 0, 0, 0, 0, 0, 0));
	} else if (count < 0) {
		term->tr_move(term, 0, y2 + count + 1);
		for (i = count; i < 0; i++)
			tput(tparm(term->TI_dl1, 0, 0, 0, 0, 0, 0, 0, 0, 0));
		term->tr_move(term, 0, y1);
		for (i = count; i < 0; i++)
			tput(tparm(term->TI_il1, 0, 0, 0, 0, 0, 0, 0, 0, 0));
	}
}

/* Clear screen (clear_screen / clear) */
static void _clear_screen(TERM_REC *term)
{
	tput(tparm(term->TI_clear, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Clear screen (clr_eos / ed) */
static void _clear_eos(TERM_REC *term)
{
	term->tr_move(term, 0, 0);
	tput(tparm(term->TI_ed, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Clear screen (parm_delete_line / dl) */
static void _clear_del(TERM_REC *term)
{
	term->tr_move(term, 0, 0);
	tput(tparm(term->TI_dl, term->height, term->height, 0, 0, 0, 0, 0, 0, 0));
}

/* Clear screen (delete_line / dl1) */
static void _clear_del_1(TERM_REC *term)
{
	int i;

	term->tr_move(term, 0, 0);
	for (i = 0; i < term->height; i++)
		tput(tparm(term->TI_dl1, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Clear to end of line (clr_eol / el) */
static void _clrtoeol(TERM_REC *term)
{
	tput(tparm(term->TI_el, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Repeat character (rep / rp) */
static void _repeat(TERM_REC *term, char chr, int count)
{
	tput(tparm(term->TI_rep, chr, count, 0, 0, 0, 0, 0, 0, 0));
}

/* Repeat character (manual) */
static void _repeat_manual(TERM_REC *term, char chr, int count)
{
	while (count > 0) {
		putc(chr, term->out);
		count--;
	}
}

/* Reset all terminal attributes */
static void _set_normal(TERM_REC *term)
{
	tput(tparm(term->TI_normal, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

static void _set_blink(TERM_REC *term)
{
	tput(tparm(term->TI_blink, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Reverse on */
static void _set_reverse(TERM_REC *term)
{
	tput(tparm(term->TI_rev, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Bold on */
static void _set_bold(TERM_REC *term)
{
	tput(tparm(term->TI_bold, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Underline on/off */
static void _set_uline(TERM_REC *term, int set)
{
	tput(tparm(set ? term->TI_smul : term->TI_rmul, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Standout on/off */
static void _set_standout(TERM_REC *term, int set)
{
	tput(tparm(set ? term->TI_smso : term->TI_rmso, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Italic on/off */
static void _set_italic(TERM_REC *term, int set)
{
	tput(tparm(set ? term->TI_sitm : term->TI_ritm, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Standout on (fallback for reverse) */
static void _set_standout_on(TERM_REC *term)
{
	_set_standout(term, TRUE);
}

inline static int color256(const TERM_REC *term, const int color) {
	if (color < term->TI_colors)
		return color;

	if (color < 16)
		return color % term->TI_colors;

	if (color < 256)
		return term_color256map[color] % term->TI_colors;

	return color % term->TI_colors;
}

/* Change foreground color */
static void _set_fg(TERM_REC *term, int color)
{
	tput(tparm(term->TI_fg[color256(term, color)], 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Change background color */
static void _set_bg(TERM_REC *term, int color)
{
	tput(tparm(term->TI_bg[color256(term, color)], 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

/* Beep */
static void _beep(TERM_REC *term)
{
	tput(tparm(term->TI_bel, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

static void _ignore(TERM_REC *term)
{
}

static void _ignore_parm(TERM_REC *term, int param)
{
}

static void terminfo_set_appkey_mode(TERM_REC *term, int set)
{
	if (term->TI_smkx && term->TI_rmkx)
		tput(tparm(set ? term->TI_smkx : term->TI_rmkx, 0, 0, 0, 0, 0, 0, 0, 0, 0));
}

static void term_dec_set_bracketed_paste_mode(int enable)
{
	if (enable)
		tputs("\e[?2004h", 0, term_putchar);
	else
		tputs("\e[?2004l", 0, term_putchar);
}

static void term_fill_capabilities(TERM_REC *term)
{
	int i, ival;
	char *sval;
        void *ptr;

	for (i = 0; i < sizeof(tcaps)/sizeof(tcaps[0]); i++) {
		ptr = G_STRUCT_MEMBER_P(term, tcaps[i].offset);

		switch (tcaps[i].type) {
		case CAP_TYPE_FLAG:
			ival = term_getflag(tcaps[i]);
                        *(int *)ptr = ival;
                        break;
		case CAP_TYPE_INT:
			ival = term_getnum(tcaps[i]);
                        *(int *)ptr = ival;
                        break;
		case CAP_TYPE_STR:
			sval = term_getstr(tcaps[i], tptr);
			if (sval == (char *) -1)
				*(char **)ptr = NULL;
			else
				*(char **)ptr = sval;
                        break;
		}
	}
}

static void terminfo_colors_deinit(TERM_REC *term)
{
	int i;

	if (terminfo_is_colors_set(term)) {
		for (i = 0; i < term->TI_colors; i++) {
			g_free(term->TI_fg[i]);
			g_free(term->TI_bg[i]);
		}

		g_free_and_null(term->TI_fg);
		g_free_and_null(term->TI_bg);
	}
}

/* Setup colors - if force is set, use ANSI-style colors if
   terminal capabilities don't contain color codes */
void terminfo_setup_colors(TERM_REC *term, int force)
{
	static const char ansitab[16] = { 0, 4, 2, 6, 1, 5, 3, 7, 8, 12, 10, 14, 9, 13, 11, 15 };
	unsigned int i, color;

	terminfo_colors_deinit(term);

	if (force && term->TI_setf == NULL && term->TI_setaf == NULL)
		term->TI_colors = 8;

	if ((term->TI_setf || term->TI_setaf || force) && term->TI_colors > 0) {
		term->TI_fg = g_new0(char *, term->TI_colors);
		term->TI_bg = g_new0(char *, term->TI_colors);
		term->tr_set_fg = _set_fg;
		term->tr_set_bg = _set_bg;
	} else {
		/* no colors */
		term->TI_colors = 0;
		term->tr_set_fg = term->tr_set_bg = _ignore_parm;
	}

	if (term->TI_setaf) {
		for (i = 0; i < term->TI_colors; i++) {
			color = i < 16 ? ansitab[i] : i;
			term->TI_fg[i] =
			    g_strdup(tparm(term->TI_setaf, color, 0, 0, 0, 0, 0, 0, 0, 0));
		}
	} else if (term->TI_setf) {
		for (i = 0; i < term->TI_colors; i++)
			term->TI_fg[i] = g_strdup(tparm(term->TI_setf, i, 0, 0, 0, 0, 0, 0, 0, 0));
	} else if (force) {
		for (i = 0; i < 8; i++)
			term->TI_fg[i] = g_strdup_printf("\033[%dm", 30 + ansitab[i]);
	}

	if (term->TI_setab) {
		for (i = 0; i < term->TI_colors; i++) {
			color = i < 16 ? ansitab[i] : i;
			term->TI_bg[i] =
			    g_strdup(tparm(term->TI_setab, color, 0, 0, 0, 0, 0, 0, 0, 0));
		}
	} else if (term->TI_setb) {
		for (i = 0; i < term->TI_colors; i++)
			term->TI_bg[i] = g_strdup(tparm(term->TI_setb, i, 0, 0, 0, 0, 0, 0, 0, 0));
	} else if (force) {
		for (i = 0; i < 8; i++)
			term->TI_bg[i] = g_strdup_printf("\033[%dm", 40 + ansitab[i]);
	}
}

static void terminfo_input_init0(TERM_REC *term)
{
	tcgetattr(fileno(term->in), &term->old_tio);
	memcpy(&term->tio, &term->old_tio, sizeof(term->tio));

	term->tio.c_lflag &= ~(ICANON | ECHO); /* CBREAK, no ECHO */
        /* Disable the ICRNL flag to disambiguate ^J and Enter, also disable the
         * software flow control to leave ^Q and ^S ready to be bound */
	term->tio.c_iflag &= ~(ICRNL | IXON | IXOFF); 
	term->tio.c_cc[VMIN] = 1; /* read() is satisfied after 1 char */
	term->tio.c_cc[VTIME] = 0; /* No timer */

        /* Disable INTR, QUIT, VDSUSP and SUSP keys */
	term->tio.c_cc[VINTR] = _POSIX_VDISABLE;
	term->tio.c_cc[VQUIT] = _POSIX_VDISABLE;
#ifdef VDSUSP
	term->tio.c_cc[VDSUSP] = _POSIX_VDISABLE;
#endif
#ifdef VSUSP
	term->tio.c_cc[VSUSP] = _POSIX_VDISABLE;
#endif

}

static void terminfo_input_init(TERM_REC *term)
{
        tcsetattr(fileno(term->in), TCSADRAIN, &term->tio);
}

static void terminfo_input_deinit(TERM_REC *term)
{
        tcsetattr(fileno(term->in), TCSADRAIN, &term->old_tio);
}

void terminfo_cont(TERM_REC *term)
{
	if (term->TI_smcup)
		tput(tparm(term->TI_smcup, 0, 0, 0, 0, 0, 0, 0, 0, 0));

	if (term->appkey_enabled)
		terminfo_set_appkey_mode(term, TRUE);

	if (term->bracketed_paste_enabled)
		term_dec_set_bracketed_paste_mode(TRUE);

        terminfo_input_init(term);
}

void terminfo_stop(TERM_REC *term)
{
        /* reset colors */
	terminfo_set_normal();
        /* move cursor to bottom of the screen */
	terminfo_move(0, term->height-1);

	if (term->bracketed_paste_enabled)
		term_dec_set_bracketed_paste_mode(FALSE);

	/* stop cup-mode */
	if (term->TI_rmcup)
		tput(tparm(term->TI_rmcup, 0, 0, 0, 0, 0, 0, 0, 0, 0));

	if (term->appkey_enabled)
		terminfo_set_appkey_mode(term, FALSE);

        /* reset input settings */
	terminfo_input_deinit(term);
        fflush(term->out);
}

static int term_setup(TERM_REC *term)
{
	GString *str;
	int err;
	char *term_env;

	term_env = getenv("TERM");
	if (term_env == NULL) {
		fprintf(stderr, "TERM environment not set\n");
		return 0;
	}

	if (setupterm(term_env, 1, &err) != 0) {
		fprintf(stderr, "setupterm() failed for TERM=%s: %d\n", term_env, err);
		return 0;
	}

	term_fill_capabilities(term);

	/* Cursor movement */
	if (term->TI_cup)
		term->tr_move = _move_cup;
	else if (term->TI_hpa && term->TI_vpa)
		term->tr_move = _move_pa;
	else {
		fprintf(stderr, "Terminal doesn't support cursor movement\n");
		return 0;
	}
	term->tr_move_relative = _move_relative;
	term->tr_set_cursor_visible =
	    term->TI_civis && term->TI_cnorm ? _set_cursor_visible : _ignore_parm;

	/* Scrolling */
	if ((term->TI_csr || term->TI_wind) && term->TI_rin && term->TI_indn)
		term->tr_scroll = _scroll_region;
	else if (term->TI_il && term->TI_dl)
		term->tr_scroll = _scroll_line;
	else if ((term->TI_csr || term->TI_wind) && term->TI_ri && term->TI_ind)
		term->tr_scroll = _scroll_region_1;
	else if (term->tr_scroll == NULL && (term->TI_il1 && term->TI_dl1))
		term->tr_scroll = _scroll_line_1;
	else if (term->tr_scroll == NULL) {
		fprintf(stderr, "Terminal doesn't support scrolling\n");
		return 0;
	}

	/* Clearing screen */
	if (term->TI_clear)
		term->tr_clear = _clear_screen;
	else if (term->TI_ed)
		term->tr_clear = _clear_eos;
	else if (term->TI_dl)
		term->tr_clear = _clear_del;
	else if (term->TI_dl1)
		term->tr_clear = _clear_del_1;
	else {
		/* we could do this by line inserts as well, but don't
		   bother - if some terminal has insert line it most probably
		   has delete line as well, if not a regular clear screen */
		fprintf(stderr, "Terminal doesn't support clearing screen\n");
		return 0;
	}

	/* Clearing to end of line */
	if (term->TI_el)
		term->tr_clrtoeol = _clrtoeol;
	else {
		fprintf(stderr, "Terminal doesn't support clearing to end of line\n");
		return 0;
	}

	/* Repeating character */
	if (term->TI_rep)
		term->tr_repeat = _repeat;
	else
		term->tr_repeat = _repeat_manual;

	/* Bold, underline, standout, reverse, italics */
	term->tr_set_blink = term->TI_blink ? _set_blink : _ignore;
	term->tr_set_bold = term->TI_bold ? _set_bold : _ignore;
	term->tr_set_reverse = term->TI_rev  ? _set_reverse :
	                       term->TI_smso ? _set_standout_on :
	                                       _ignore;
	term->tr_set_uline = term->TI_smul && term->TI_rmul ? _set_uline : _ignore_parm;
	term->tr_set_standout = term->TI_smso && term->TI_rmso ? _set_standout : _ignore_parm;
	term->tr_set_italic = term->TI_sitm && term->TI_ritm ? _set_italic : _ignore_parm;

	/* Create a string to set all attributes off */
	str = g_string_new(NULL);
	if (term->TI_sgr0)
		g_string_append(str, term->TI_sgr0);
	if (term->TI_rmul &&
	    (term->TI_sgr0 == NULL || g_strcmp0(term->TI_rmul, term->TI_sgr0) != 0))
		g_string_append(str, term->TI_rmul);
	if (term->TI_rmso &&
	    (term->TI_sgr0 == NULL || g_strcmp0(term->TI_rmso, term->TI_sgr0) != 0))
		g_string_append(str, term->TI_rmso);
	if (term->TI_ritm &&
	    (term->TI_sgr0 == NULL || g_strcmp0(term->TI_ritm, term->TI_sgr0) != 0))
		g_string_append(str, term->TI_ritm);
	term->TI_normal = g_string_free_and_steal(str);
	term->tr_set_normal = _set_normal;

	term->tr_beep = term->TI_bel ? _beep : _ignore;

	terminfo_setup_colors(term, FALSE);
	terminfo_input_init0(term);
	terminfo_cont(term);
	return 1;
}

void term_set_appkey_mode(int enable)
{
	if (current_term->appkey_enabled == enable)
		return;

	current_term->appkey_enabled = enable;
	terminfo_set_appkey_mode(current_term, enable);
}

void term_set_bracketed_paste_mode(int enable)
{
	if (current_term->bracketed_paste_enabled == enable)
		return;

	current_term->bracketed_paste_enabled = enable;
	term_dec_set_bracketed_paste_mode(enable);
}

TERM_REC *terminfo_core_init(FILE *in, FILE *out)
{
	TERM_REC *old_term, *term;

        old_term = current_term;
	current_term = term = g_new0(TERM_REC, 1);

	term->in = in;
	term->out = out;

	if (!term_setup(term)) {
		g_free(term);
                term = NULL;
	}

	current_term = old_term;
        return term;
}

void terminfo_core_deinit(TERM_REC *term)
{
	TERM_REC *old_term;

	old_term = current_term;
	current_term = term;
	term->tr_set_normal(term);
	current_term = old_term;

	terminfo_stop(term);

	g_free(term->TI_normal);
	terminfo_colors_deinit(term);

	g_free(term);
}
