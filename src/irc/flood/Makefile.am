plugindir = $(libdir)/irssi/plugins
plugin_LTLIBRARIES = libirc_flood.la

INCLUDES = $(GLIB_CFLAGS) \
	-I$(top_srcdir)/src -I$(top_srcdir)/src/core/ -I$(top_srcdir)/src/irc/core/

libirc_flood_la_SOURCES = \
	autoignore.c \
	flood.c

noinst_HEADERS = \
	autoignore.h \
	flood.h
