SUBDIRS = dcc flood notifylist

noinst_LTLIBRARIES = libfe_common_irc.la

INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

libfe_common_irc_la_SOURCES = \
	fe-channels.c \
	fe-irc-commands.c \
	fe-irc-server.c \
	fe-ircnet.c \
	fe-ctcp.c \
	fe-events.c \
	fe-events-numeric.c \
	fe-ignore.c \
	fe-netjoin.c \
	fe-netsplit.c \
	fe-query.c \
	fe-common-irc.c \
	irc-completion.c \
	irc-window-activity.c \
	irc-hilight-text.c \
        irc-modules.c \
	module-formats.c 

noinst_HEADERS = \
	fe-common-irc.h \
	fe-query.h \
	irc-hilight-text.h \
	module.h \
	module-formats.h
