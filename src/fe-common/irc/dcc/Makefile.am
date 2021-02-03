noinst_LIBRARIES = libfe_irc_dcc.a

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/irc/dcc/ \
	-I$(top_srcdir)/src/fe-common/core/ \
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
