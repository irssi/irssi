noinst_LIBRARIES = libcore.a

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core \
	$(GLIB_CFLAGS) \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DMODULEDIR=\""$(libdir)/irssi/modules"\"

if USE_GREGEX
regex_impl=iregex-gregex.c
else
regex_impl=iregex-regexh.c
endif

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
	utf8.c \
	$(regex_impl) \
	wcwidth.c \
	wcwidth-wrapper.c \
	tls.c \
	write-buffer.c

if HAVE_CAPSICUM
libcore_a_SOURCES += \
	capsicum.c
endif

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
	capsicum.h \
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
	network-openssl.h \
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
	utf8.h \
	iregex.h \
	window-item-def.h \
	tls.h \
	write-buffer.h \
	$(structure_headers)
