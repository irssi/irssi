bin_PROGRAMS = botti

INCLUDES = $(GLIB_CFLAGS)

INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/

botti_DEPENDENCIES = @COMMON_NOUI_LIBS@

botti_LDADD = \
	@COMMON_NOUI_LIBS@ \
	$(PROG_LIBS) \
	$(PERL_LDFLAGS)

botti_SOURCES = \
        irssi.c

noinst_HEADERS = \
	module.h
