moduledir = $(libdir)/irssi/modules
module_LTLIBRARIES = libproxy.la

libproxy_la_LDFLAGS = -avoid-version

INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src -I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/

libproxy_la_SOURCES = \
	proxy.c \
	dump.c \
	listen.c

noinst_HEADERS = \
	proxy.h \
	module.h
