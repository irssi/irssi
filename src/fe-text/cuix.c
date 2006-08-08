#include "module.h"
#include "settings.h"
#include "cuix-api.h"
#include "cuix-lib.h"
#include "cuix.h"
#include "term.h"
#if defined(USE_NCURSES) && !defined(RENAMED_NCURSES)
#  include <ncurses.h>
#else
#  include <curses.h>
#endif


void cuix_destroy (void)
{
    if (cuix_win) {
        del_panel (p_cuix);
        delwin(cuix_win);
    }
    cuix_win = NULL;
    cuix_active = 0;
    update_panels ();
    doupdate();
    term_refresh (root_window);
    irssi_redraw ();
}

void cuix_create(void)
{
    home_menu (NULL);
    cuix_destroy ();
}

void cuix_refresh (void)
{
    update_panels ();
}


