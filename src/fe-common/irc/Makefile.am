SUBDIRS = dcc notifylist

noinst_LIBRARIES = libfe_common_irc.a

INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

libfe_common_irc_a_SOURCES = \
	fe-irc-channels.c \
	fe-irc-commands.c \
	fe-irc-messages.c \
	fe-irc-queries.c \
	fe-irc-server.c \
	fe-ircnet.c \
	fe-ctcp.c \
	fe-events.c \
	fe-events-numeric.c \
	fe-modes.c \
	fe-netjoin.c \
	fe-netsplit.c \
	fe-common-irc.c \
        irc-modules.c \
	module-formats.c 

noinst_HEADERS = \
	module.h \
	module-formats.h
