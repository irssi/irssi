moduledir = $(libdir)/irssi/modules
module_LTLIBRARIES = libperl.la

libperl_la_LDFLAGS = -avoid-version

perl.c: perl-signals.h

INCLUDES = $(GLIB_CFLAGS) \
	-DSCRIPTDIR=\""$(libdir)/irssi/scripts"\" \
	$(PERL_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core

libperl_la_SOURCES = \
	perl.c \
	perl-common.c \
	xsinit.c

perl-signals.h: $(top_srcdir)/docs/signals.txt $(srcdir)/get-signals.pl
	cat $(top_srcdir)/docs/signals.txt | $(perlpath) $(srcdir)/get-signals.pl > perl-signals.h

CORE_SOURCES = \
	core/Channel.xs \
	core/Core.xs \
	core/Log.xs \
	core/Masks.xs \
	core/Query.xs \
	core/Rawlog.xs \
	core/Server.xs \
	core/Settings.xs \
	core/Window.xs \
	core/Irssi.xs \
	core/Irssi.pm \
	core/Makefile.PL.in \
	core/typemap \
	core/module.h

IRC_SOURCES = \
	irc/Bans.xs \
	irc/Dcc.xs \
	irc/Flood.xs \
	irc/Ignore.xs \
	irc/IrcChannel.xs \
	irc/IrcQuery.xs \
	irc/IrcServer.xs \
	irc/Modes.xs \
	irc/Netsplit.xs \
	irc/Notifylist.xs \
	irc/Irc.xs \
	irc/Irc.pm \
	irc/Makefile.PL.in \
	irc/typemap \
	irc/module.h

EXTRA_DIST = \
	libperl_dynaloader.la \
	libperl_orig.la \
	get-signals.pl \
	$(CORE_SOURCES) \
	$(IRC_SOURCES)

noinst_HEADERS = \
	module.h \
	perl-common.h

all-local:
	for dir in common irc; do cd $$dir && if [ ! -f Makefile ]; then if [ "x$(PERL_LIB_DIR)" = "x" ]; then $(perlpath) Makefile.PL; else $(perlpath) Makefile.PL LIB=$(PERL_LIB_DIR); fi; fi && $(MAKE) && cd ..; done

install-exec-local:
	for dir in common irc; do cd $$dir && make install && cd ..; done

libperl_la_LIBADD = $(PERL_LDFLAGS)
