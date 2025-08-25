#ifndef IRSSI_FE_TEXT_TERM_H
#define IRSSI_FE_TEXT_TERM_H

typedef struct _TERM_WINDOW TERM_WINDOW;

#define FG_MASK        ( 0x00ff )
#define BG_MASK        ( 0xff00 )
#define BG_SHIFT       8

/* text attributes */
#define ATTR_RESETFG	( 0x010000 )
#define ATTR_RESETBG	( 0x020000 )
#define ATTR_BOLD	( 0x040000 )
#define ATTR_BLINK	( 0x080000 )
#define ATTR_UNDERLINE	( 0x100000 )
#define ATTR_REVERSE	( 0x200000 )
#define ATTR_ITALIC	( 0x400000 )
#define ATTR_FGCOLOR24	( 0x1000000 )
#define ATTR_BGCOLOR24	( 0x2000000 )

#define ATTR_RESET	(ATTR_RESETFG|ATTR_RESETBG)

#define ATTR_NOCOLORS (ATTR_UNDERLINE|ATTR_REVERSE|ATTR_BLINK|ATTR_BOLD|ATTR_ITALIC)

/* terminal types */
#define TERM_TYPE_8BIT		0 /* normal 8bit text */
#define TERM_TYPE_UTF8		1
#define TERM_TYPE_BIG5		2

#include <irssi/src/core/utf8.h>

extern TERM_WINDOW *root_window;
extern int term_width, term_height;
extern int term_use_colors, term_type;
extern int term_use_colors24;
extern int term_color256map[];

/* Initialize / deinitialize terminal */
int term_init(void);
void term_deinit(void);

/* Gets the current terminal size, returns TRUE if ok. */
int term_get_size(int *width, int *height);

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

#define term_set_color(window, col) term_set_color2(window, (col) &~(ATTR_FGCOLOR24|ATTR_BGCOLOR24), UINT_MAX, UINT_MAX)
void term_set_color2(TERM_WINDOW *window, int col, unsigned int fgcol24, unsigned int bgcol24);

void term_move(TERM_WINDOW *window, int x, int y);
void term_addch(TERM_WINDOW *window, char chr);
void term_add_unichar(TERM_WINDOW *window, unichar chr);
int  term_addstr(TERM_WINDOW *window, const char *str);
void term_clrtoeol(TERM_WINDOW *window);
void term_window_clrtoeol(TERM_WINDOW* window, int ypos);
void term_window_clrtoeol_abs(TERM_WINDOW* window, int ypos_abs);

void term_move_cursor(int x, int y);

void term_refresh_freeze(void);
void term_refresh_thaw(void);
void term_refresh(TERM_WINDOW *window);

void term_stop(void);

void term_set_appkey_mode(int enable);
void term_set_bracketed_paste_mode(int enable);

/* keyboard input handling */
void term_set_input_type(int type);
void term_gets(GArray *buffer, int *line_count);

/* internal */
void term_common_init(void);
void term_common_deinit(void);

void term_environment_check(void);

#endif
