noinst_LIBRARIES = libfe_irc_notifylist.a

AM_CPPFLAGS = \
	-I$(top_builddir) \
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

EXTRA_DIST = meson.build
