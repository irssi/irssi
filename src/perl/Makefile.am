noinst_LTLIBRARIES = libperl.la

irssi-perl.c: perl-signals.h

INCLUDES = $(GLIB_CFLAGS) \
	-DPLUGINSDIR=\""$(libdir)/irssi/plugins"\" \
	-DSCRIPTDIR=\""$(libdir)/irssi/scripts"\" \
	$(PERL_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core

libperl_la_SOURCES = \
	irssi-perl.c \
	xsinit.c

perl-signals.h: $(top_srcdir)/docs/signals.txt $(srcdir)/get-signals.pl
	cat $(top_srcdir)/docs/signals.txt | $(perlpath) $(srcdir)/get-signals.pl > perl-signals.h

EXTRA_DIST = \
	get-signals.pl \
	xs/Irssi-bans.xs \
	xs/Irssi-channel.xs \
	xs/Irssi-core.xs \
	xs/Irssi-dcc.xs \
	xs/Irssi-flood.xs \
	xs/Irssi-ignore.xs \
	xs/Irssi-log.xs \
	xs/Irssi-masks.xs \
	xs/Irssi-modes.xs \
	xs/Irssi-netsplit.xs \
	xs/Irssi-notifylist.xs \
	xs/Irssi-query.xs \
	xs/Irssi-rawlog.xs \
	xs/Irssi-server.xs \
	xs/Irssi-settings.xs \
	xs/Irssi-window.xs \
	xs/Irssi.xs \
	xs/Irssi.pm \
	xs/Makefile.PL.in \
	xs/typemap

noinst_HEADERS = \
	module.h \
	xs/module.h

all-local:
	cd xs && if [ ! -f Makefile ]; then $(perlpath) Makefile.PL; fi && $(MAKE) && cd ..

install-exec-local:
	cd xs && make install && cd ..
