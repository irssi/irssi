SUBDIRS = dcc notifylist

noinst_LIBRARIES = libfe_common_irc.a

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	$(GLIB_CFLAGS) \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

real_sources = \
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
	fe-whois.c \
	irc-completion.c \
	module-formats.c 

libfe_common_irc_a_SOURCES = \
	$(real_sources) \
        irc-modules.c

pkginc_fe_common_ircdir=$(pkgincludedir)/src/fe-common/irc
pkginc_fe_common_irc_HEADERS = \
	fe-irc-server.h \
	module.h \
	module-formats.h

DISTFILES = $(DIST_COMMON) $(real_sources) $(HEADERS) $(TEXINFOS) $(EXTRA_DIST)

distclean-generic:
	rm -f irc-modules.c
