#ifndef IRSSI_CORE_CORE_H
#define IRSSI_CORE_CORE_H

#include <irssi/src/common.h>

/* for determining what GUI is currently in use: */
#define IRSSI_GUI_NONE	0
#define IRSSI_GUI_TEXT	1
#define IRSSI_GUI_GTK	2
#define IRSSI_GUI_GNOME	3
#define IRSSI_GUI_QT   	4
#define IRSSI_GUI_KDE  	5

extern int irssi_gui;
extern int irssi_init_finished; /* TRUE after "irssi init finished" signal is sent */
extern int sighup_received; /* TRUE after received SIGHUP. */
extern int sigterm_received; /* TRUE after received SIGTERM. */
extern time_t client_start_time;

void core_preinit(const char *path);

void core_register_options(void);
void core_init(void);
void core_deinit(void);

#endif
