#ifndef __SCREEN_H
#define __SCREEN_H

typedef struct _SCREEN_WINDOW SCREEN_WINDOW;

#define ATTR_UNDERLINE 0x100
#define ATTR_COLOR8    0x200
#define ATTR_REVERSE   0x400

/* XXX I hope this could be integrated into BX.
 * XXX Well, this should be done via libc,
 *     but FreeBSD libc support is quite LAME.
 *     Macro below are copied from lynx.
 *
 *				clive@FreeBSD.org
 */
#ifdef WANT_BIG5
/* XXX I didn't check the encoding range of big5+. This is standard big5. */
#  define is_big5_los(lo) (((char)0x40<=lo)&&(lo<=(char)0x7E))	/* standard */
#  define is_big5_lox(lo) (((char)0x80<=lo)&&(lo<=(char)0xFE))	/* extended */
#  define is_big5_hi(hi)  (((char)0x81<=hi)&&(hi<=(char)0xFE))
#  define is_big5(hi,lo) is_big5_hi(hi) && (is_big5_los(lo) || is_big5_lox(lo))
#endif

extern SCREEN_WINDOW *screen_root;
extern int screen_width, screen_height;

int init_screen(void); /* Initialize screen, detect screen length */
void deinit_screen(void); /* Deinitialize screen */

int screen_has_colors(void);
void screen_clear(void);

SCREEN_WINDOW *screen_window_create(int x, int y, int width, int height);
void screen_window_destroy(SCREEN_WINDOW *window);

void screen_window_clear(SCREEN_WINDOW *window);
void screen_window_move(SCREEN_WINDOW *window, int x, int y,
			int width, int height);
void screen_window_scroll(SCREEN_WINDOW *window, int count);

void screen_set_color(SCREEN_WINDOW *window, int col);
void screen_set_bg(SCREEN_WINDOW *window, int col);

void screen_move(SCREEN_WINDOW *window, int x, int y);
void screen_addch(SCREEN_WINDOW *window, int chr);
void screen_addstr(SCREEN_WINDOW *window, char *str);
void screen_clrtoeol(SCREEN_WINDOW *window);

void screen_move_cursor(int x, int y);

void screen_refresh_freeze(void);
void screen_refresh_thaw(void);
void screen_refresh(SCREEN_WINDOW *window);

int screen_getch(void);

#endif
