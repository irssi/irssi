moduledir = $(libdir)/irssi/modules
module_LTLIBRARIES = libirc_notifylist.la

INCLUDES = $(GLIB_CFLAGS) \
	-I$(top_srcdir)/src -I$(top_srcdir)/src/core/ -I$(top_srcdir)/src/irc/core/

libirc_notifylist_la_SOURCES = \
	notifylist.c \
	notify-commands.c \
	notify-ison.c \
	notify-setup.c \
	notify-whois.c

noinst_HEADERS = \
	notifylist.h \
	notify-setup.h \
	module.h
