noinst_LTLIBRARIES = libcore.la

INCLUDES = \
	$(GLIB_CFLAGS) \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core

if BUILD_MEMDEBUG
memdebug_src=memdebug.c
else
memdebug_src=
endif

libcore_la_SOURCES = \
	args.c \
	commands.c \
	core.c \
        levels.c \
	line-split.c \
	log.c \
        $(memdebug_src) \
	misc.c \
	modules.c \
	net-disconnect.c \
	net-nonblock.c \
	network.c \
	pidwait.c \
	rawlog.c \
	server.c \
	server-redirect.c \
	settings.c \
	signals.c \
	special-vars.c

noinst_HEADERS = \
	args.h \
	commands.h \
	core.h \
        levels.h \
	line-split.h \
	log.h \
        memdebug.h \
	misc.h \
	module.h \
	modules.h \
	net-disconnect.h \
	net-internal.h \
	net-nonblock.h \
	network.h \
	pidwait.h \
	rawlog.h \
	server.h \
	server-redirect.h \
	settings.h \
	signals.h \
	special-vars.h

EXTRA_DIST = \
	memdebug.c
