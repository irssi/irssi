bin_PROGRAMS = irssi-bot

INCLUDES = $(GLIB_CFLAGS)

INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/

irssi_bot_DEPENDENCIES = @IRC_LIBS@ @CORE_LIBS@

irssi_bot_LDADD = \
	@IRC_LIBS@ \
	@CORE_LIBS@ \
        $(PROG_LIBS) \
	$(INTLLIBS) \
	$(PERL_LDFLAGS)

irssi_bot_SOURCES = \
        irssi.c

noinst_HEADERS = \
	module.h
