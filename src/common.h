#ifndef __COMMON_H
#define __COMMON_H

#define IRSSI_AUTHOR "Timo Sirainen <cras@irccrew.org>"
#define IRSSI_WEBSITE "http://xlife.dhs.org/irssi/"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#  ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>

#ifdef HAVE_POPT_H
#include <popt.h>
#else
#  ifdef HAVE_POPT_GNOME_H
#    include <popt-gnome.h>
#  endif
#endif

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_DIRENT_H
#  include <dirent.h>
#endif
#include <fcntl.h>

#ifdef HAVE_SOCKS_H
#include <socks.h>
#endif

#include <netdb.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>
#include <gmodule.h>

typedef struct
{
    gushort family;
#ifdef HAVE_IPV6
    struct in6_addr addr;
#else
    struct in_addr addr;
#endif
}
IPADDR;

#include "irc-base/memdebug.h"
#include "lib-config/irssi-config.h"
#include "common-setup.h"

/* GUI library must provide these functions: */

typedef enum
{
  GUI_INPUT_READ       = 1 << 0,
  GUI_INPUT_WRITE      = 1 << 1,
  GUI_INPUT_EXCEPTION  = 1 << 2
} GUIInputCondition;

typedef void (*GUIInputFunction) (gpointer data, gint handle, GUIInputCondition condition);
typedef gint (*GUITimeoutFunction) (gpointer data);

gint gui_input_add(gint handle, GUIInputCondition condition,
                   GUIInputFunction function, gpointer data);
void gui_input_remove(gint tag);

guint gui_timeout_add(guint32 interval, GUITimeoutFunction function, gpointer data);
void gui_timeout_remove(gint tag);

#endif
