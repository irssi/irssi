#include "module.h"
#include "signals.h"
#include "terminfo-core.h"

#ifndef _POSIX_VDISABLE
#  define _POSIX_VDISABLE 0
#endif

#define tput(s) tputs(s, 0, term_putchar)
inline static int term_putchar(int c)
{
        return fputc(c, current_term->out);
}

/* Don't bother including curses.h because of these -
   they might not even be defined there */
char *tparm();
int tputs();

#ifdef HAVE_TERMINFO
int setupterm();
char *tigetstr();
int tigetnum();
int tigetflag();
#define term_getstr(x, buffer) tigetstr(x.ti_name)
#define term_getnum(x) tigetnum(x.ti_name);
#define term_getflag(x) tigetflag(x.ti_name);
#else
int tgetent();
char *tgetstr();
int tgetnum();
int tgetflag();
#define term_getstr(x, buffer) tgetstr(x.tc_name, &buffer)
#define term_getnum(x) tgetnum(x.tc_name)
#define term_getflag(x) tgetflag(x.tc_name)
#endif

#define CAP_TYPE_FLAG	0
#define CAP_TYPE_INT	1
#define CAP_TYPE_STR	2

typedef struct {
        const char *ti_name; /* terminfo name */
	const char *tc_name; /* termcap name */
	int type;
	unsigned int offset;
} TERMINFO_REC;

TERM_REC *current_term;

/* Define only what we might need */
static TERMINFO_REC tcaps[] = {
        /* Terminal size */
	{ "cols",	"co",	CAP_TYPE_INT,	G_STRUCT_OFFSET(TERM_REC, width) },
	{ "lines",	"li",	CAP_TYPE_INT,	G_STRUCT_OFFSET(TERM_REC, height) },

        /* Cursor movement */
	{ "smcup",	"ti",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_smcup) },
	{ "rmcup",	"te",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_rmcup) },
	{ "cup",	"cm",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_cup) },
	{ "hpa",	"ch",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_hpa) },
	{ "vpa",	"vh",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_vpa) },
	{ "cub1",	"le",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_cub1) },
	{ "cuf1",	"nd",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_cuf1) },
	{ "civis",	"vi",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_civis) },
	{ "cnorm",	"ve",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_cnorm) },

        /* Scrolling */
	{ "csr",      	"cs",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_csr) },
	{ "wind",      	"wi",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_wind) },
	{ "ri",      	"sr",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_ri) },
	{ "rin",      	"SR",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_rin) },
	{ "ind",      	"sf",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_ind) },
	{ "indn",      	"SF",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_indn) },
	{ "il",      	"AL",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_il) },
	{ "il1",      	"al",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_il1) },
	{ "dl",      	"DL",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_dl) },
	{ "dl1",      	"dl",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_dl1) },

	/* Clearing screen */
	{ "clear",     	"cl",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_clear) },
	{ "ed",     	"cd",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_ed) },

        /* Clearing to end of line */
	{ "el",     	"ce",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_el) },

        /* Repeating character */
	{ "rep",     	"rp",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_rep) },

	/* Colors */
	{ "colors",	"Co",   CAP_TYPE_INT,   G_STRUCT_OFFSET(TERM_REC, TI_colors) },
	{ "sgr0",     	"me",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_sgr0) },
	{ "smul",     	"us",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_smul) },
	{ "rmul",     	"ue",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_rmul) },
	{ "smso",     	"so",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_smso) },
	{ "rmso",     	"se",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_rmso) },
	{ "bold",     	"md",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_bold) },
	{ "blink",     	"mb",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_blink) },
	{ "setaf",     	"AF",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_setaf) },
	{ "setab",     	"AB",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_setab) },
	{ "setf",     	"Sf",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_setf) },
	{ "setb",     	"Sb",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_setb) },

        /* Beep */
	{ "bel",     	"bl",	CAP_TYPE_STR,	G_STRUCT_OFFSET(TERM_REC, TI_bel) },
};

/* Move cursor (cursor_address / cup) */
static void _move_cup(TERM_REC *term, int x, int y)
{
	tput(tparm(term->TI_cup, y, x));
}

/* Move cursor (column_address+row_address / hpa+vpa) */
static void _move_pa(TERM_REC *term, int x, int y)
{
	tput(tparm(term->TI_hpa, x));
	tput(tparm(term->TI_vpa, y));
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
			tput(tparm(term->TI_cub1));
                        return;
		}
		if (x == oldx+1 && y == oldy && term->TI_cuf1) {
			tput(tparm(term->TI_cuf1));
                        return;
		}
	}

        /* fallback to absolute positioning */
	if (term->TI_cup) {
		tput(tparm(term->TI_cup, y, x));
                return;
	}

	if (oldy != y)
		tput(tparm(term->TI_vpa, y));
        if (oldx != x)
		tput(tparm(term->TI_hpa, x));
}

/* Set cursor visible/invisible */
static void _set_cursor_visible(TERM_REC *term, int set)
{
	tput(tparm(set ? term->TI_cnorm : term->TI_civis));
}

#define scroll_region_setup(term, y1, y2) \
	if ((term)->TI_csr != NULL) \
		tput(tparm((term)->TI_csr, y1, y2)); \
	else if ((term)->TI_wind != NULL) \
		tput(tparm((term)->TI_wind, y1, y2, 0, (term)->width-1));

/* Scroll (change_scroll_region+parm_rindex+parm_index / csr+rin+indn) */
static void _scroll_region(TERM_REC *term, int y1, int y2, int count)
{
        /* setup the scrolling region to wanted area */
        scroll_region_setup(term, y1, y2);

	term->move(term, 0, y1);
	if (count > 0) {
		term->move(term, 0, y2);
		tput(tparm(term->TI_indn, count, count));
	} else if (count < 0) {
		term->move(term, 0, y1);
		tput(tparm(term->TI_rin, -count, -count));
	}

        /* reset the scrolling region to full screen */
        scroll_region_setup(term, 0, term->height-1);
}

/* Scroll (change_scroll_region+scroll_reverse+scroll_forward / csr+ri+ind) */
static void _scroll_region_1(TERM_REC *term, int y1, int y2, int count)
{
	int i;

        /* setup the scrolling region to wanted area */
        scroll_region_setup(term, y1, y2);

	if (count > 0) {
		term->move(term, 0, y2);
		for (i = 0; i < count; i++)
			tput(tparm(term->TI_ind));
	} else if (count < 0) {
		term->move(term, 0, y1);
		for (i = count; i < 0; i++)
			tput(tparm(term->TI_ri));
	}

        /* reset the scrolling region to full screen */
        scroll_region_setup(term, 0, term->height-1);
}

/* Scroll (parm_insert_line+parm_delete_line / il+dl) */
static void _scroll_line(TERM_REC *term, int y1, int y2, int count)
{
	/* setup the scrolling region to wanted area -
	   this might not necessarily work with il/dl, but at least it
	   looks better if it does */
        scroll_region_setup(term, y1, y2);

	if (count > 0) {
		term->move(term, 0, y1);
		tput(tparm(term->TI_dl, count, count));
		term->move(term, 0, y2-count+1);
		tput(tparm(term->TI_il, count, count));
	} else if (count < 0) {
		term->move(term, 0, y2+count+1);
		tput(tparm(term->TI_dl, -count, -count));
		term->move(term, 0, y1);
		tput(tparm(term->TI_il, -count, -count));
	}

        /* reset the scrolling region to full screen */
        scroll_region_setup(term, 0, term->height-1);
}

/* Scroll (insert_line+delete_line / il1+dl1) */
static void _scroll_line_1(TERM_REC *term, int y1, int y2, int count)
{
	int i;

	if (count > 0) {
		term->move(term, 0, y1);
                for (i = 0; i < count; i++)
			tput(tparm(term->TI_dl1));
		term->move(term, 0, y2-count+1);
                for (i = 0; i < count; i++)
			tput(tparm(term->TI_il1));
	} else if (count < 0) {
		term->move(term, 0, y2+count+1);
		for (i = count; i < 0; i++)
			tput(tparm(term->TI_dl1));
		term->move(term, 0, y1);
		for (i = count; i < 0; i++)
			tput(tparm(term->TI_il1));
	}
}

/* Clear screen (clear_screen / clear) */
static void _clear_screen(TERM_REC *term)
{
	tput(tparm(term->TI_clear));
}

/* Clear screen (clr_eos / ed) */
static void _clear_eos(TERM_REC *term)
{
        term->move(term, 0, 0);
	tput(tparm(term->TI_ed));
}

/* Clear screen (parm_delete_line / dl) */
static void _clear_del(TERM_REC *term)
{
        term->move(term, 0, 0);
	tput(tparm(term->TI_dl, term->height, term->height));
}

/* Clear screen (delete_line / dl1) */
static void _clear_del_1(TERM_REC *term)
{
	int i;

	term->move(term, 0, 0);
        for (i = 0; i < term->height; i++)
		tput(tparm(term->TI_dl1));
}

/* Clear to end of line (clr_eol / el) */
static void _clrtoeol(TERM_REC *term)
{
	tput(tparm(term->TI_el));
}

/* Repeat character (rep / rp) */
static void _repeat(TERM_REC *term, char chr, int count)
{
	tput(tparm(term->TI_rep, chr, count));
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
	tput(tparm(term->TI_normal));
}

static void _set_blink(TERM_REC *term)
{
	tput(tparm(term->TI_blink));
}

/* Bold on */
static void _set_bold(TERM_REC *term)
{
	tput(tparm(term->TI_bold));
}

/* Underline on/off */
static void _set_uline(TERM_REC *term, int set)
{
	tput(tparm(set ? term->TI_smul : term->TI_rmul));
}

/* Standout on/off */
static void _set_standout(TERM_REC *term, int set)
{
	tput(tparm(set ? term->TI_smso : term->TI_rmso));
}

/* Change foreground color */
static void _set_fg(TERM_REC *term, int color)
{
	tput(tparm(term->TI_fg[color % term->TI_colors]));
}

/* Change background color */
static void _set_bg(TERM_REC *term, int color)
{
	tput(tparm(term->TI_bg[color % term->TI_colors]));
}

/* Beep */
static void _beep(TERM_REC *term)
{
	tput(tparm(term->TI_bel));
}

static void _ignore(TERM_REC *term)
{
}

static void _ignore_parm(TERM_REC *term, int param)
{
}

static void term_fill_capabilities(TERM_REC *term)
{
	int i, ival;
	char *sval;
        void *ptr;

#ifndef HAVE_TERMINFO
	char *tptr = term->buffer2;
#endif
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
	static const char ansitab[16] = {
		0, 4, 2, 6, 1, 5, 3, 7,
		8, 12, 10, 14, 9, 13, 11, 15
	};
	unsigned int i, color;

	terminfo_colors_deinit(term);

	if (force && term->TI_setf == NULL && term->TI_setaf == NULL)
		term->TI_colors = 8;

	if ((term->TI_setf || term->TI_setaf || force) &&
	     term->TI_colors > 0) {
		term->TI_fg = g_new0(char *, term->TI_colors);
		term->TI_bg = g_new0(char *, term->TI_colors);
		term->set_fg = _set_fg;
		term->set_bg = _set_bg;
	} else {
		/* no colors */
		term->TI_colors = 0;
		term->set_fg = term->set_bg = _ignore_parm;
	}

	if (term->TI_setaf) {
		for (i = 0; i < term->TI_colors; i++) {
			color = i < 16 ? ansitab[i] : i;
			term->TI_fg[i] = g_strdup(tparm(term->TI_setaf, color, 0));
		}
	} else if (term->TI_setf) {
		for (i = 0; i < term->TI_colors; i++)
                        term->TI_fg[i] = g_strdup(tparm(term->TI_setf, i, 0));
	} else if (force) {
		for (i = 0; i < 8; i++)
                        term->TI_fg[i] = g_strdup_printf("\033[%dm", 30+ansitab[i]);
	}

	if (term->TI_setab) {
		for (i = 0; i < term->TI_colors; i++) {
			color = i < 16 ? ansitab[i] : i;
			term->TI_bg[i] = g_strdup(tparm(term->TI_setab, color, 0));
		}
	} else if (term->TI_setb) {
		for (i = 0; i < term->TI_colors; i++)
                        term->TI_bg[i] = g_strdup(tparm(term->TI_setb, i, 0));
	} else if (force) {
		for (i = 0; i < 8; i++)
                        term->TI_bg[i] = g_strdup_printf("\033[%dm", 40+ansitab[i]);
	}
}

static void terminfo_input_init(TERM_REC *term)
{
	tcgetattr(fileno(term->in), &term->old_tio);
	memcpy(&term->tio, &term->old_tio, sizeof(term->tio));

	term->tio.c_lflag &= ~(ICANON | ECHO); /* CBREAK, no ECHO */
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

        tcsetattr(fileno(term->in), TCSADRAIN, &term->tio);

}

static void terminfo_input_deinit(TERM_REC *term)
{
        tcsetattr(fileno(term->in), TCSADRAIN, &term->old_tio);
}

void terminfo_cont(TERM_REC *term)
{
	if (term->TI_smcup)
                tput(tparm(term->TI_smcup));
        terminfo_input_init(term);
}

void terminfo_stop(TERM_REC *term)
{
        /* reset colors */
	terminfo_set_normal();
        /* move cursor to bottom of the screen */
	terminfo_move(0, term->height-1);

	/* stop cup-mode */
	if (term->TI_rmcup)
		tput(tparm(term->TI_rmcup));

        /* reset input settings */
	terminfo_input_deinit(term);
        fflush(term->out);
}

static int term_setup(TERM_REC *term)
{
	GString *str;
#ifdef HAVE_TERMINFO
	int err;
#endif
        char *term_env;

	term_env = getenv("TERM");
	if (term_env == NULL) {
		fprintf(stderr, "TERM environment not set\n");
                return 0;
	}

#ifdef HAVE_TERMINFO
	if (setupterm(term_env, 1, &err) != 0) {
		fprintf(stderr, "setupterm() failed for TERM=%s: %d\n", term_env, err);
		return 0;
	}
#else
	if (tgetent(term->buffer1, term_env) < 1)
	{
		fprintf(stderr, "Termcap not found for TERM=%s\n", term_env);
		return 0;
	}
#endif

        term_fill_capabilities(term);

	/* Cursor movement */
	if (term->TI_cup)
		term->move = _move_cup;
	else if (term->TI_hpa && term->TI_vpa)
		term->move = _move_pa;
	else {
                fprintf(stderr, "Terminal doesn't support cursor movement\n");
		return 0;
	}
	term->move_relative = _move_relative;
	term->set_cursor_visible = term->TI_civis && term->TI_cnorm ?
		_set_cursor_visible : _ignore_parm;

        /* Scrolling */
	if ((term->TI_csr || term->TI_wind) && term->TI_rin && term->TI_indn)
		term->scroll = _scroll_region;
	else if (term->TI_il && term->TI_dl)
		term->scroll = _scroll_line;
	else if ((term->TI_csr || term->TI_wind) && term->TI_ri && term->TI_ind)
		term->scroll = _scroll_region_1;
	else if (term->scroll == NULL && (term->TI_il1 && term->TI_dl1))
		term->scroll = _scroll_line_1;
	else if (term->scroll == NULL) {
                fprintf(stderr, "Terminal doesn't support scrolling\n");
		return 0;
	}

	/* Clearing screen */
	if (term->TI_clear)
		term->clear = _clear_screen;
	else if (term->TI_ed)
		term->clear = _clear_eos;
	else if (term->TI_dl)
		term->clear = _clear_del;
	else if (term->TI_dl1)
		term->clear = _clear_del_1;
	else {
		/* we could do this by line inserts as well, but don't
		   bother - if some terminal has insert line it most probably
		   has delete line as well, if not a regular clear screen */
                fprintf(stderr, "Terminal doesn't support clearing screen\n");
		return 0;
	}

	/* Clearing to end of line */
	if (term->TI_el)
		term->clrtoeol = _clrtoeol;
	else {
                fprintf(stderr, "Terminal doesn't support clearing to end of line\n");
		return 0;
	}

	/* Repeating character */
	if (term->TI_rep)
		term->repeat = _repeat;
	else
		term->repeat = _repeat_manual;

	/* Bold, underline, standout */
	term->set_blink = term->TI_blink ? _set_blink : _ignore;
	term->set_bold = term->TI_bold ? _set_bold : _ignore;
	term->set_uline = term->TI_smul && term->TI_rmul ?
		_set_uline : _ignore_parm;
	term->set_standout = term->TI_smso && term->TI_rmso ?
		_set_standout : _ignore_parm;

        /* Create a string to set all attributes off */
        str = g_string_new(NULL);
	if (term->TI_sgr0)
		g_string_append(str, term->TI_sgr0);
	if (term->TI_rmul && (term->TI_sgr0 == NULL || strcmp(term->TI_rmul, term->TI_sgr0) != 0))
		g_string_append(str, term->TI_rmul);
	if (term->TI_rmso && (term->TI_sgr0 == NULL || strcmp(term->TI_rmso, term->TI_sgr0) != 0))
		g_string_append(str, term->TI_rmso);
        term->TI_normal = str->str;
	g_string_free(str, FALSE);
        term->set_normal = _set_normal;

	term->beep = term->TI_bel ? _beep : _ignore;

	terminfo_setup_colors(term, FALSE);
        terminfo_cont(term);
        return 1;
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
	term->set_normal(term);
        current_term = old_term;

        terminfo_stop(term);

	g_free(term->TI_normal);
	terminfo_colors_deinit(term);

        g_free(term);
}
