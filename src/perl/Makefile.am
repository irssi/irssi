noinst_LTLIBRARIES = libperl.la

libperl_la_DEPENDENCIES = perl-signals.h

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
	xs/Irssi.xs \
	xs/Irssi.pm \
	xs/Makefile.PL.in \
	xs/typemap

all-local:
	cd xs && if [ ! -f Makefile ]; then $(perlpath) Makefile.PL; fi && $(MAKE) && cd ..

install-exec-local:
	cd xs && make install && cd ..
