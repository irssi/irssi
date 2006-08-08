#ifndef __CUIX_LIB_H
#define __CUIX_LIB_H

#if defined(USE_NCURSES) && !defined(RENAMED_NCURSES)
#  include <ncurses.h>
#else
#  include <curses.h>
#endif
#include <form.h>
#include <panel.h>
#include "cuix-api.h"

int home_menu (char *);


#endif /* __CUIX_LIB_H */
