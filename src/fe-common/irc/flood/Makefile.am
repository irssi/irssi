plugindir = $(libdir)/irssi/plugins
plugin_LTLIBRARIES = libfe_common_irc_flood.la

INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

libfe_common_irc_flood_la_SOURCES = \
	fe-flood.c \
	module-formats.c

noinst_HEADERS = \
	module.h \
	module-formats.h
