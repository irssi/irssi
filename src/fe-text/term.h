#ifndef __TERM_H
#define __TERM_H

typedef struct _TERM_WINDOW TERM_WINDOW;

#define ATTR_RESETFG	0x0100
#define ATTR_RESETBG	0x0200
#define ATTR_BOLD	0x0400
#define ATTR_BLINK      0x0800
#define ATTR_UNDERLINE	0x1000
#define ATTR_REVERSE	0x2000

#define ATTR_RESET	(ATTR_RESETFG|ATTR_RESETBG)

#define ATTR_NOCOLORS (ATTR_UNDERLINE|ATTR_REVERSE)

#ifdef WANT_BIG5
/* XXX I didn't check the encoding range of big5+. This is standard big5. */
#  define is_big5_los(lo) (((char)0x40<=lo)&&(lo<=(char)0x7E))	/* standard */
#  define is_big5_lox(lo) (((char)0x80<=lo)&&(lo<=(char)0xFE))	/* extended */
#  define is_big5_hi(hi)  (((char)0x81<=hi)&&(hi<=(char)0xFE))
#  define is_big5(hi,lo) is_big5_hi(hi) && (is_big5_los(lo) || is_big5_lox(lo))
#endif

extern TERM_WINDOW *root_window;
extern int term_width, term_height, term_use_colors, term_detached;

/* Initialize / deinitialize terminal */
int term_init(void);
void term_deinit(void);

/* Resize terminal - if width or height is negative,
   the new size is unknown and should be figured out somehow */
void term_resize(int width, int height);
void term_resize_final(int width, int height);
/* Resize the terminal if needed */
void term_resize_dirty(void);

/* Returns TRUE if terminal has colors */
int term_has_colors(void);
/* Force the colors on any way you can */
void term_force_colors(int set);

/* Clear screen */
void term_clear(void);
/* Beep */
void term_beep(void);

/* Create a new window in terminal */
TERM_WINDOW *term_window_create(int x, int y, int width, int height);
/* Destroy a terminal window */
void term_window_destroy(TERM_WINDOW *window);

/* Move/resize window */
void term_window_move(TERM_WINDOW *window, int x, int y,
		      int width, int height);
/* Clear window */
void term_window_clear(TERM_WINDOW *window);
/* Scroll window up/down */
void term_window_scroll(TERM_WINDOW *window, int count);

void term_set_color(TERM_WINDOW *window, int col);

void term_move(TERM_WINDOW *window, int x, int y);
void term_addch(TERM_WINDOW *window, int chr);
void term_addstr(TERM_WINDOW *window, const char *str);
void term_clrtoeol(TERM_WINDOW *window);

void term_move_cursor(int x, int y);

void term_refresh_freeze(void);
void term_refresh_thaw(void);
void term_refresh(TERM_WINDOW *window);

/* Automatically detach irssi when terminal is lost */
void term_auto_detach(int set);
void term_detach(void);
void term_attach(FILE *in, FILE *out);

void term_stop(void);
int term_gets(unsigned char *buffer, int size);

/* internal */
void term_common_init(void);
void term_common_deinit(void);

#endif
