/* This contains all the necessary includes for creating GUI widgets to
   plugins */

#ifdef HAVE_GTK
#include "gui-gnome/irssi.h"
#include "gui-gnome/setup-int.h"
#endif

#if defined (HAVE_CURSES) || defined (HAVE_SLANG)
#include "gui-text/irssi.h"
#endif

#undef MODULE_NAME
