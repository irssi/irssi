moduledir = $(libdir)/irssi/modules
module_LTLIBRARIES = libirc_dcc.la

libirc_dcc_la_LDFLAGS = -avoid-version

INCLUDES = $(GLIB_CFLAGS) \
	-I$(top_srcdir)/src -I$(top_srcdir)/src/core/ -I$(top_srcdir)/src/irc/core/

libirc_dcc_la_SOURCES = \
	dcc.c \
	dcc-chat.c \
	dcc-files.c

noinst_HEADERS = \
	dcc.h \
	module.h
