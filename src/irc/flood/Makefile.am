noinst_LIBRARIES = libirc_flood.a

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	$(GLIB_CFLAGS)

libirc_flood_a_SOURCES = \
	autoignore.c \
	flood.c

pkginc_irc_flooddir=$(pkgincludedir)/src/irc/flood
pkginc_irc_flood_HEADERS = \
	module.h
