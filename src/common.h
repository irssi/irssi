#ifndef __COMMON_H
#define __COMMON_H

#define IRSSI_AUTHOR "Timo Sirainen <tss@iki.fi>"
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
#  include <popt.h>
#else
#  include "lib-popt/popt.h"
#endif

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_DIRENT_H
#  include <dirent.h>
#endif
#include <fcntl.h>

#include <glib.h>
#include <gmodule.h>

#include "irc-base/memdebug.h"
#include "lib-config/irssi-config.h"
#include "common-setup.h"
#include "nls.h"

typedef enum
{
	G_INPUT_READ       = 1 << 0,
	G_INPUT_WRITE      = 1 << 1,
	G_INPUT_EXCEPTION  = 1 << 2
} GInputCondition;

typedef void (*GInputFunction) (gpointer data, int source,
				GInputCondition condition);

int g_input_add(int source, GInputCondition condition,
		GInputFunction function, gpointer data);

#define MAX_INT_STRLEN ((sizeof(int) * CHAR_BIT + 2) / 3 + 1)

#endif
