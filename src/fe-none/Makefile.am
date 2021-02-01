bin_PROGRAMS = botti

AM_CPPFLAGS = \
	-I$(top_builddir) \
	$(GLIB_CFLAGS)

botti_DEPENDENCIES = @COMMON_NOUI_LIBS@

botti_LDADD = \
	@COMMON_NOUI_LIBS@ \
	@PERL_LINK_LIBS@ \
	@PERL_LINK_FLAGS@ \
	@PROG_LIBS@

botti_SOURCES = \
        irssi.c

noinst_HEADERS = \
	module.h

EXTRA_DIST = meson.build
