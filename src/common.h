#ifndef __COMMON_H
#define __COMMON_H

#define IRSSI_AUTHOR "Timo Sirainen <tss@iki.fi>"
#define IRSSI_WEBSITE "http://irssi.org/"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stddef.h>
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
#ifdef WIN32
#  include <win32-compat.h>
#endif

#include <glib.h>
#ifdef HAVE_GMODULE
#  include <gmodule.h>
#endif

#include "core/memdebug.h"

#define g_free_not_null(a) \
	G_STMT_START { \
	  if (a) g_free(a); \
	} G_STMT_END

#define g_free_and_null(a) \
	G_STMT_START { \
	  if (a) { g_free(a); (a) = NULL; } \
	} G_STMT_END

#define G_INPUT_READ	(1 << 0)
#define G_INPUT_WRITE	(1 << 1)

typedef void (*GInputFunction) (void *data, GIOChannel *source, int condition);

int g_input_add(GIOChannel *source, int condition,
		GInputFunction function, void *data);
int g_input_add_full(GIOChannel *source, int priority, int condition,
		     GInputFunction function, void *data);

#define MAX_INT_STRLEN ((sizeof(int) * CHAR_BIT + 2) / 3 + 1)

typedef struct _IPADDR IPADDR;
typedef struct _CONFIG_REC CONFIG_REC;
typedef struct _CONFIG_NODE CONFIG_NODE;

typedef struct _LINEBUF_REC LINEBUF_REC;
typedef struct _NET_SENDBUF_REC NET_SENDBUF_REC;
typedef struct _RAWLOG_REC RAWLOG_REC;

typedef struct _CHATNET_REC CHATNET_REC;
typedef struct _SERVER_REC SERVER_REC;
typedef struct _WI_ITEM_REC WI_ITEM_REC;
typedef struct _CHANNEL_REC CHANNEL_REC;
typedef struct _QUERY_REC QUERY_REC;
typedef struct _NICK_REC NICK_REC;

typedef struct _SERVER_CONNECT_REC SERVER_CONNECT_REC;
typedef struct _SERVER_SETUP_REC SERVER_SETUP_REC;
typedef struct _CHANNEL_SETUP_REC CHANNEL_SETUP_REC;

#endif
