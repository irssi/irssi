noinst_LIBRARIES = libfe_irc_notifylist.a

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	$(GLIB_CFLAGS) \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

libfe_irc_notifylist_a_SOURCES = \
	fe-notifylist.c \
	module-formats.c

pkginc_fe_common_irc_notifylistdir=$(pkgincludedir)/src/fe-common/irc/notifylist
pkginc_fe_common_irc_notifylist_HEADERS = \
	module.h \
	module-formats.h
