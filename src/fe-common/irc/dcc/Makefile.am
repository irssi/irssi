noinst_LTLIBRARIES = libfe_common_irc_dcc.la

INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

libfe_common_irc_dcc_la_SOURCES = \
	fe-dcc.c \
	module-formats.c

noinst_HEADERS = \
	module.h \
	module-formats.h
