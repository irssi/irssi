moduledir = $(libdir)/irssi/modules
module_LTLIBRARIES = libirssi_perl.la

irssi-perl.c: perl-signals.h

INCLUDES = $(GLIB_CFLAGS) \
	-DSCRIPTDIR=\""$(libdir)/irssi/scripts"\" \
	$(PERL_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core

libirssi_perl_la_SOURCES = \
	irssi-perl.c \
	xsinit.c

perl-signals.h: $(top_srcdir)/docs/signals.txt $(srcdir)/get-signals.pl
	cat $(top_srcdir)/docs/signals.txt | $(perlpath) $(srcdir)/get-signals.pl > perl-signals.h

EXTRA_DIST = \
	libperl_dynaloader.la \
	get-signals.pl \
	core/Irssi-bans.xs \
	core/Irssi-channel.xs \
	core/Irssi-core.xs \
	core/Irssi-dcc.xs \
	core/Irssi-flood.xs \
	core/Irssi-ignore.xs \
	core/Irssi-log.xs \
	core/Irssi-masks.xs \
	core/Irssi-modes.xs \
	core/Irssi-netsplit.xs \
	core/Irssi-notifylist.xs \
	core/Irssi-query.xs \
	core/Irssi-rawlog.xs \
	core/Irssi-server.xs \
	core/Irssi-settings.xs \
	core/Irssi-window.xs \
	core/Irssi.xs \
	core/Irssi.pm \
	core/Makefile.PL.in \
	core/typemap

noinst_HEADERS = \
	module.h \
	core/module.h \
	irc/module.h

all-local:
	for dir in core irc; do cd $$dir && if [ ! -f Makefile ]; then if [ "x$(PERL_LIB_DIR)" = "x" ]; then $(perlpath) Makefile.PL; else $(perlpath) Makefile.PL LIB=$(PERL_LIB_DIR); fi; fi && $(MAKE) && cd ..; done

install-exec-local:
	for dir in core irc; do cd $$dir && make install && cd ..; done

libirssi_perl_la_LIBADD = $(PERL_LDFLAGS)
