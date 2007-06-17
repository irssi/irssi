#if defined(USE_NCURSES) && !defined(RENAMED_NCURSES)
#  include <ncurses.h>
#else
#  include <curses.h>
#endif

struct _TERM_WINDOW {
	int x, y;
        int width, height;
	WINDOW *win;
};
