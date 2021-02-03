noinst_LIBRARIES = libirssi_config.a

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir)/src \
	$(GLIB_CFLAGS)

libirssi_config_a_SOURCES = \
	get.c \
	set.c \
	parse.c \
	write.c

pkginc_lib_configdir=$(pkgincludedir)/src/lib-config
pkginc_lib_config_HEADERS = \
	iconfig.h \
	module.h
