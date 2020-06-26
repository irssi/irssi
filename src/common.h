#ifndef IRSSI_COMMON_H
#define IRSSI_COMMON_H

#define IRSSI_DIR_FULL "%s/.irssi" /* %s == g_get_home_dir() */

#define IRSSI_GLOBAL_CONFIG "irssi.conf" /* config file name in /etc/ */
#define IRSSI_HOME_CONFIG "config" /* config file name in ~/.irssi/ */

#define IRSSI_ABI_VERSION 30

#define DEFAULT_SERVER_ADD_PORT 6667
#define DEFAULT_SERVER_ADD_TLS_PORT 6697

#include <irssi/irssi-config.h>

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif
#include <sys/stat.h>

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_DIRENT_H
#  include <dirent.h>
#endif
#include <fcntl.h>

#include <glib.h>
#ifdef HAVE_GMODULE
#  include <gmodule.h>
#endif

typedef guint64 uoff_t;
#define PRIuUOFF_T G_GUINT64_FORMAT

/* input functions */
#define G_INPUT_READ	(1 << 0)
#define G_INPUT_WRITE	(1 << 1)

typedef void (*GInputFunction) (void *data, GIOChannel *source, int condition);

int g_input_add(GIOChannel *source, int condition,
		GInputFunction function, void *data);
int g_input_add_full(GIOChannel *source, int priority, int condition,
		     GInputFunction function, void *data);

/* return full path for ~/.irssi */
const char *get_irssi_dir(void);
/* return full path for ~/.irssi/config */
const char *get_irssi_config(void);

/* max. size for %d */
#define MAX_INT_STRLEN ((sizeof(int) * CHAR_BIT + 2) / 3 + 1)

#define g_free_not_null(a) g_free(a)

#define g_free_and_null(a) \
	G_STMT_START { \
	  if (a) { g_free(a); (a) = NULL; } \
	} G_STMT_END

/* ctype.h isn't safe with chars, use our own instead */
#define i_toupper(x) toupper((int) (unsigned char) (x))
#define i_tolower(x) tolower((int) (unsigned char) (x))
#define i_isalnum(x) isalnum((int) (unsigned char) (x))
#define i_isalpha(x) isalpha((int) (unsigned char) (x))
#define i_isascii(x) isascii((int) (unsigned char) (x))
#define i_isblank(x) isblank((int) (unsigned char) (x))
#define i_iscntrl(x) iscntrl((int) (unsigned char) (x))
#define i_isdigit(x) isdigit((int) (unsigned char) (x))
#define i_isgraph(x) isgraph((int) (unsigned char) (x))
#define i_islower(x) islower((int) (unsigned char) (x))
#define i_isprint(x) isprint((int) (unsigned char) (x))
#define i_ispunct(x) ispunct((int) (unsigned char) (x))
#define i_isspace(x) isspace((int) (unsigned char) (x))
#define i_isupper(x) isupper((int) (unsigned char) (x))
#define i_isxdigit(x) isxdigit((int) (unsigned char) (x))

typedef struct _IPADDR IPADDR;

typedef struct _LINEBUF_REC LINEBUF_REC;
typedef struct _NET_SENDBUF_REC NET_SENDBUF_REC;
typedef struct _RAWLOG_REC RAWLOG_REC;

typedef struct _CHAT_PROTOCOL_REC CHAT_PROTOCOL_REC;
typedef struct _CHATNET_REC CHATNET_REC;
typedef struct _SERVER_REC SERVER_REC;
typedef struct _WI_ITEM_REC WI_ITEM_REC;
typedef struct _CHANNEL_REC CHANNEL_REC;
typedef struct _QUERY_REC QUERY_REC;
typedef struct _NICK_REC NICK_REC;

typedef struct _SERVER_CONNECT_REC SERVER_CONNECT_REC;
typedef struct _SERVER_SETUP_REC SERVER_SETUP_REC;
typedef struct _CHANNEL_SETUP_REC CHANNEL_SETUP_REC;

typedef struct _WINDOW_REC WINDOW_REC;

#endif
