LIBTOOL = $(PERL_LIBTOOL)

moduledir = $(libdir)/irssi/modules

module_LTLIBRARIES = $(module_lib)
noinst_LTLIBRARIES = $(static_lib)
EXTRA_LTLIBRARIES = libperl.la libperl_static.la

libperl_la_LDFLAGS = -avoid-version -rpath $(moduledir)

perl.c: perl-signals-list.h

INCLUDES = $(GLIB_CFLAGS) \
	-DSCRIPTDIR=\""$(libdir)/irssi/scripts"\" \
	$(PERL_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core

perl_sources = \
	perl.c \
	perl-common.c \
	perl-signals.c \
	xsinit.c

libperl_la_DEPENDENCIES = .libs/libperl_orig.a .libs/DynaLoader.a

.libs/libperl_orig.a:
	if [ ! -d .libs ]; then mkdir .libs; fi
	rm -f .libs/libperl_orig.a
	if [ x$(LIBPERL_A) = x ]; then touch .libs/libperl_orig.a; else $(LN_S) $(LIBPERL_A) .libs/libperl_orig.a; fi
.libs/DynaLoader.a:
	if [ ! -d .libs ]; then mkdir .libs; fi
	rm -f .libs/DynaLoader.a
	$(LN_S) $(DYNALOADER_A) .libs/DynaLoader.a

libperl_la_SOURCES = \
	$(perl_sources)

libperl_static_la_SOURCES = \
	$(perl_sources)

perl-signals-list.h: $(top_srcdir)/docs/signals.txt $(srcdir)/get-signals.pl
	cat $(top_srcdir)/docs/signals.txt | $(perlpath) $(srcdir)/get-signals.pl > perl-signals-list.h

CORE_SOURCES = \
	common/Channel.xs \
	common/Core.xs \
	common/Ignore.xs \
	common/Log.xs \
	common/Masks.xs \
	common/Query.xs \
	common/Rawlog.xs \
	common/Server.xs \
	common/Settings.xs \
	common/Themes.xs \
	common/Window.xs \
	common/Irssi.xs \
	common/Irssi.pm \
	common/Makefile.PL.in \
	common/typemap \
	common/module.h

IRC_SOURCES = \
	irc/Bans.xs \
	irc/Dcc.xs \
	irc/Flood.xs \
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
	perl-common.h \
	perl-signals.h

all-local:
	for dir in common irc; do cd $$dir && if [ ! -f Makefile ]; then if [ "x$(PERL_LIB_DIR)" = "x" ]; then $(perlpath) Makefile.PL; else $(perlpath) Makefile.PL LIB=$(PERL_LIB_DIR); fi; fi && if ! $(MAKE); then $(MAKE); fi && cd ..; done

install-exec-local:
	for dir in common irc; do cd $$dir && make install && cd ..; done

clean-generic:
	rm -f common/Irssi.c irc/Irc.c

libperl_la_LIBADD = $(PERL_LDFLAGS)
