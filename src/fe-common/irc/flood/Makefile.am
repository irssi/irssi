moduledir = $(libdir)/irssi/modules
module_LTLIBRARIES = libfe_irc_flood.la

libfe_irc_flood_la_LDFLAGS = -avoid-version

INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

libfe_irc_flood_la_SOURCES = \
	fe-flood.c \
	module-formats.c

noinst_HEADERS = \
	module.h \
	module-formats.h
