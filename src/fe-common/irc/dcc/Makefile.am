moduledir = $(libdir)/irssi/modules
module_LTLIBRARIES = libfe_common_irc_dcc.la

libfe_common_irc_dcc_la_LDFLAGS = -avoid-version

INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/irc/dcc/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

libfe_common_irc_dcc_la_SOURCES = \
	fe-dcc.c \
	fe-dcc-chat.c \
	fe-dcc-get.c \
	fe-dcc-send.c \
	module-formats.c

noinst_HEADERS = \
	module.h \
	module-formats.h
