moduledir = $(libdir)/irssi/modules
module_LTLIBRARIES = libirc_proxy.la

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	$(GLIB_CFLAGS)

libirc_proxy.a:
	rm -f libirc_proxy.a
	$(LN_S) .libs/libirc_proxy.a libirc_proxy.a

libirc_proxy_la_LDFLAGS = -module -avoid-version

libirc_proxy_la_DEPENDENCIES = libirc_proxy.a

libirc_proxy_la_SOURCES = \
	proxy.c \
	dump.c \
	listen.c

noinst_HEADERS = \
	module.h \
	proxy.h

clean-generic:
	rm -f libirc_proxy.a
