noinst_LIBRARIES = libpopt.a

INCLUDES = \
	-I$(top_srcdir)/src \
	$(GLIB_CFLAGS)

libpopt_a_SOURCES = \
	findme.c popt.c poptconfig.c popthelp.c poptparse.c

pkginc_libpoptdir=$(pkgincludedir)/src/lib-popt
pkginc_libpopt_HEADERS = \
	findme.h popt.h poptint.h
