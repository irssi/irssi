noinst_LIBRARIES = libcore.a

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core \
	$(GLIB_CFLAGS) \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DMODULEDIR=\""$(libdir)/irssi/modules"\"

libcore_a_SOURCES = \
	args.c \
	channels.c \
	channels-setup.c \
	commands.c \
	chat-commands.c \
	chat-protocols.c \
	chatnets.c \
	core.c \
	expandos.c \
        ignore.c \
        levels.c \
	line-split.c \
	log.c \
	log-away.c \
	masks.c \
	misc.c \
	modules.c \
	modules-load.c \
	net-disconnect.c \
	net-nonblock.c \
	net-sendbuffer.c \
	network.c \
	network-openssl.c \
	nicklist.c \
	nickmatch-cache.c \
	pidwait.c \
	queries.c \
	rawlog.c \
	recode.c \
	servers.c \
	servers-reconnect.c \
	servers-setup.c \
	session.c \
	settings.c \
	signals.c \
	special-vars.c \
	write-buffer.c

structure_headers = \
	channel-rec.h \
	channel-setup-rec.h \
	chatnet-rec.h \
	query-rec.h \
	server-rec.h \
	server-setup-rec.h \
	server-connect-rec.h \
	window-item-rec.h

pkginc_coredir=$(pkgincludedir)/src/core
pkginc_core_HEADERS = \
	args.h \
	channels.h \
	channels-setup.h \
	commands.h \
	chat-protocols.h \
	chatnets.h \
	core.h \
	expandos.h \
        ignore.h \
        levels.h \
	line-split.h \
	log.h \
	masks.h \
	misc.h \
	module.h \
	modules.h \
	modules-load.h \
	net-disconnect.h \
	net-nonblock.h \
	net-sendbuffer.h \
	network.h \
	nick-rec.h \
	nicklist.h \
	nickmatch-cache.h \
	pidwait.h \
	queries.h \
	rawlog.h \
	recode.h \
	servers.h \
	servers-reconnect.h \
	servers-setup.h \
	session.h \
	settings.h \
	signals.h \
	special-vars.h \
	window-item-def.h \
	write-buffer.h \
	$(structure_headers)
