noinst_LTLIBRARIES = libirc_core.la

INCLUDES = \
	$(GLIB_CFLAGS) \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-I$(top_srcdir)/src -I$(top_srcdir)/src/core

libirc_core_la_SOURCES = \
	bans.c \
        ctcp.c \
        channels.c \
        channels-query.c \
        channels-setup.c \
        channel-events.c \
        channel-rejoin.c \
        ignore.c \
        irc.c \
        irc-core.c \
        irc-commands.c \
        irc-log.c \
        irc-rawlog.c \
        irc-server.c \
        irc-special-vars.c \
	ircnet-setup.c \
        lag.c \
        masks.c \
        massjoin.c \
        modes.c \
        mode-lists.c \
        netsplit.c \
        nicklist.c \
        query.c \
        server-idle.c \
        server-reconnect.c \
        server-setup.c

noinst_HEADERS = \
	bans.h \
        ctcp.h \
        channels.h \
        channels-setup.h \
        ignore.h \
        irc.h \
        irc-commands.h \
        irc-server.h \
	ircnet-setup.h \
        masks.h \
        modes.h \
        mode-lists.h \
	module.h \
        netsplit.h \
        nicklist.h \
        query.h \
        server-idle.h \
        server-reconnect.h \
        server-setup.h
