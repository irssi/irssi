bin_PROGRAMS = botti

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
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
