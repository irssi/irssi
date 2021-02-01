noinst_LIBRARIES = libfe_irc_dcc.a

AM_CPPFLAGS = \
	-I$(top_builddir) \
	$(GLIB_CFLAGS) \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

libfe_irc_dcc_a_SOURCES = \
	fe-dcc.c \
	fe-dcc-chat.c \
	fe-dcc-chat-messages.c \
	fe-dcc-get.c \
	fe-dcc-send.c \
	module-formats.c \
	fe-dcc-server.c

pkginc_fe_common_irc_dccdir=$(pkgincludedir)/src/fe-common/irc/dcc
pkginc_fe_common_irc_dcc_HEADERS = \
	module.h \
	module-formats.h \
	fe-dcc.h

EXTRA_DIST = meson.build
