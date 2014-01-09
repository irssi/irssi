#ifndef __TERMINFO_CORE_H
#define __TERMINFO_CORE_H

#include <termios.h>

#define terminfo_move(x, y) current_term->move(current_term, x, y)
#define terminfo_move_relative(oldx, oldy, x, y) current_term->move_relative(current_term, oldx, oldy, x, y)
#define terminfo_set_cursor_visible(set) current_term->set_cursor_visible(current_term, set)
#define terminfo_scroll(y1, y2, count) current_term->scroll(current_term, y1, y2, count)
#define terminfo_clear() current_term->clear(current_term)
#define terminfo_clrtoeol() current_term->clrtoeol(current_term)
#define terminfo_repeat(chr, count) current_term->repeat(current_term, chr, count)
#define terminfo_set_fg(color) current_term->set_fg(current_term, color)
#define terminfo_set_bg(color) current_term->set_bg(current_term, color)
#define terminfo_set_normal() current_term->set_normal(current_term)
#define terminfo_set_bold() current_term->set_bold(current_term)
#define terminfo_set_uline(set) current_term->set_uline(current_term, set)
#define terminfo_set_standout(set) current_term->set_standout(current_term, set)
#define terminfo_is_colors_set(term) (term->TI_fg != NULL)
#define terminfo_beep(term) current_term->beep(current_term)

typedef struct _TERM_REC TERM_REC;

struct _TERM_REC {
        /* Functions */
	void (*move)(TERM_REC *term, int x, int y);
	void (*move_relative)(TERM_REC *term, int oldx, int oldy, int x, int y);
	void (*set_cursor_visible)(TERM_REC *term, int set);
	void (*scroll)(TERM_REC *term, int y1, int y2, int count);

        void (*clear)(TERM_REC *term);
	void (*clrtoeol)(TERM_REC *term);
	void (*repeat)(TERM_REC *term, char chr, int count);

	void (*set_fg)(TERM_REC *term, int color);
	void (*set_bg)(TERM_REC *term, int color);
	void (*set_normal)(TERM_REC *term);
	void (*set_blink)(TERM_REC *term);
	void (*set_bold)(TERM_REC *term);
	void (*set_uline)(TERM_REC *term, int set);
	void (*set_standout)(TERM_REC *term, int set);

        void (*beep)(TERM_REC *term);

#ifndef HAVE_TERMINFO
	char buffer1[1024], buffer2[1024];
#endif
	FILE *in, *out;
	struct termios tio, old_tio;

        /* Terminal size */
        int width, height;

        /* Cursor movement */
	const char *TI_smcup, *TI_rmcup, *TI_cup;
	const char *TI_hpa, *TI_vpa, *TI_cub1, *TI_cuf1;
        const char *TI_civis, *TI_cnorm;

	/* Scrolling */
	const char *TI_csr, *TI_wind;
	const char *TI_ri, *TI_rin, *TI_ind, *TI_indn;
	const char *TI_il, *TI_il1, *TI_dl, *TI_dl1;

	/* Clearing screen */
	const char *TI_clear, *TI_ed; /* + *TI_dl, *TI_dl1; */

        /* Clearing to end of line */
	const char *TI_el;

	/* Repeating character */
	const char *TI_rep;

	/* Colors */
	int TI_colors; /* numbers of colors in TI_fg[] and TI_bg[] */
	const char *TI_sgr0; /* turn off all attributes */
	const char *TI_smul, *TI_rmul; /* underline on/off */
        const char *TI_smso, *TI_rmso; /* standout on/off */
        const char *TI_bold, *TI_blink;
	const char *TI_setaf, *TI_setab, *TI_setf, *TI_setb;

        /* Colors - generated and dynamically allocated */
	char **TI_fg, **TI_bg, *TI_normal;

	/* Beep */
        char *TI_bel;
};

extern TERM_REC *current_term;

TERM_REC *terminfo_core_init(FILE *in, FILE *out);
void terminfo_core_deinit(TERM_REC *term);

/* Setup colors - if force is set, use ANSI-style colors if
   terminal capabilities don't contain color codes */
void terminfo_setup_colors(TERM_REC *term, int force);

void terminfo_cont(TERM_REC *term);
void terminfo_stop(TERM_REC *term);

#endif
