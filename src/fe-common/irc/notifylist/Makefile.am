noinst_LTLIBRARIES = libfe_common_irc_notifylist.la

INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

libfe_common_irc_notifylist_la_SOURCES = \
	fe-notifylist.c \
	module-formats.c

noinst_headers = \
	module-formats.h
