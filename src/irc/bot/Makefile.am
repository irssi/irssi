moduledir = $(libdir)/irssi/modules
module_LTLIBRARIES = libirc_bot.la

libirc_bot_la_LDFLAGS = -avoid-version

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	$(GLIB_CFLAGS)

libirc_bot_la_LIBADD = -lcrypt

libirc_bot_la_SOURCES = \
	bot.c \
	bot-irc-commands.c \
	bot-events.c \
	bot-users.c \
        botnet.c \
        botnet-connection.c \
	botnet-users.c

noinst_HEADERS = \
	bot.h \
	bot-users.h \
	botnet.h \
	botnet-users.h \
	module.h

EXTRA_DIST = \
	users.sample \
	botnets.sample
