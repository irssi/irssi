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

#ifdef MEM_DEBUG

void ig_mem_profile(void);

void ig_set_data(gchar *data);

gpointer ig_malloc(gint size, gchar *file, gint line);
gpointer ig_malloc0(gint size, gchar *file, gint line);
gpointer ig_realloc(gpointer mem, gulong size, gchar *file, gint line);
gchar *ig_strdup(const char *str, gchar *file, gint line);
gchar *ig_strconcat(const char *str, ...);
gchar *ig_strdup_printf(const gchar *format, ...) G_GNUC_PRINTF (1, 2);
void ig_free(gpointer p);
GString *ig_string_new(gchar *str);
void ig_string_free(GString *str, gboolean freeit);

#define g_malloc(a) ig_malloc(a, __FILE__, __LINE__)
#define g_malloc0(a) ig_malloc0(a, __FILE__, __LINE__)
#define g_realloc(a,b) ig_realloc(a, b, __FILE__, __LINE__)
#define g_strdup(a) ig_strdup(a, __FILE__, __LINE__)
#define g_strconcat ig_strconcat
#define g_strdup_printf ig_strdup_printf
#define g_strdup_vprintf ig_strdup_vprintf
#define g_free ig_free
#define g_string_new ig_string_new
#define g_string_free ig_string_free

#endif

#endif
