plugindir = $(libdir)/irssi/plugins
plugin_LTLIBRARIES = libirc_bot.la

INCLUDES = $(GLIB_CFLAGS) \
	-I$(top_srcdir)/src -I$(top_srcdir)/src/core/ -I$(top_srcdir)/src/irc/core/

libirc_bot_la_LIBADD = -lcrypt

libirc_bot_la_SOURCES = \
	bot.c \
	bot-commands.c \
	bot-events.c \
	bot-users.c \
        botnet.c \
        botnet-connection.c

noinst_HEADERS = \
	bot.h \
	botnet.h \
	bot-users.h

EXTRA_DIST = \
	users.sample \
	botnets.sample
