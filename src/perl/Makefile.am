LIBTOOL = $(PERL_LIBTOOL)

moduledir = $(libdir)/irssi/modules

module_LTLIBRARIES = $(module_lib)
noinst_LTLIBRARIES = $(static_lib)
EXTRA_LTLIBRARIES = libperl.la libperl_static.la

libperl_la_LDFLAGS = -avoid-version -rpath $(moduledir)

perl.c: perl-signals.h

INCLUDES = $(GLIB_CFLAGS) \
	-DSCRIPTDIR=\""$(libdir)/irssi/scripts"\" \
	$(PERL_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core

perl_sources = \
	perl.c \
	perl-common.c \
	xsinit.c

libperl_la_DEPENDENCIES = .libs/libperl_orig.a .libs/DynaLoader.a

.libs/libperl_orig.a:
	if [ ! -d .libs ]; then mkdir .libs; fi
	rm -f .libs/libperl_orig.a
	$(LN_S) $(LIBPERL_A) .libs/libperl_orig.a
.libs/DynaLoader.a:
	if [ ! -d .libs ]; then mkdir .libs; fi
	rm -f .libs/DynaLoader.a
	$(LN_S) $(DYNALOADER_A) .libs/DynaLoader.a

libperl_la_SOURCES = \
	$(perl_sources)

libperl_static_la_SOURCES = \
	$(perl_sources)

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
