#ifndef IRSSI_FE_TEXT_SIDEPANELS_H
#define IRSSI_FE_TEXT_SIDEPANELS_H

#include <glib.h>
#include <irssi/src/common.h>

void sidepanels_init(void);
void sidepanels_deinit(void);

/* Feed one key (unichar) from sig_gui_key_pressed; returns TRUE if consumed by mouse parser. */
gboolean sidepanels_try_parse_mouse_key(unichar key);

#endif