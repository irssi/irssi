#ifndef __COMMON_H
#define __COMMON_H

#define IRSSI_AUTHOR "Timo Sirainen <tss@iki.fi>"
#define IRSSI_WEBSITE "http://irssi.org"

#ifdef HAVE_CONFIG_H
#include <config.h>
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
#include <sys/time.h>
#include <sys/stat.h>

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_DIRENT_H
#  include <dirent.h>
#endif
#include <fcntl.h>

#include <glib.h>
#include <gmodule.h>

#include "core/memdebug.h"
#include "nls.h"

#define g_free_not_null(a) \
	if (a) g_free(a);

#define g_free_and_null(a) \
	if (a) { g_free(a); (a) = NULL; }

typedef enum {
	G_INPUT_READ       = 1 << 0,
	G_INPUT_WRITE      = 1 << 1
} GInputCondition;

typedef void (*GInputFunction) (void *data, int source,
				GInputCondition condition);

int g_input_add(int source, GInputCondition condition,
		GInputFunction function, void *data);
int g_input_add_full(int source, int priority, GInputCondition condition,
		     GInputFunction function, void *data);

#define MAX_INT_STRLEN ((sizeof(int) * CHAR_BIT + 2) / 3 + 1)

#endif
