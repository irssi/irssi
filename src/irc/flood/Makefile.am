noinst_LIBRARIES = libirc_flood.a

AM_CPPFLAGS = \
	-I$(top_builddir) \
	$(GLIB_CFLAGS)

libirc_flood_a_SOURCES = \
	autoignore.c \
	flood.c

pkginc_irc_flooddir=$(pkgincludedir)/src/irc/flood
pkginc_irc_flood_HEADERS = \
	module.h

EXTRA_DIST = meson.build
