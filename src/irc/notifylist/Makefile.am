noinst_LIBRARIES = libirc_notifylist.a

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	$(GLIB_CFLAGS)

libirc_notifylist_a_SOURCES = \
	notifylist.c \
	notify-commands.c \
	notify-ison.c \
	notify-setup.c \
	notify-whois.c

pkginc_irc_notifylistdir=$(pkgincludedir)/src/irc/notifylist
pkginc_irc_notifylist_HEADERS = \
	notifylist.h \
	notify-setup.h \
	module.h
