LIBTOOL = $(PERL_LIBTOOL)

moduledir = $(libdir)/irssi/modules

module_LTLIBRARIES = $(perl_module_lib) $(perl_module_fe_lib)
noinst_LTLIBRARIES = $(perl_static_lib) $(perl_static_fe_lib)
EXTRA_LTLIBRARIES = \
	libperl_core.la libfe_perl.la \
	libperl_core_static.la libfe_perl_static.la

libperl_core_la_LDFLAGS = -avoid-version -rpath $(moduledir)
libfe_perl_la_LDFLAGS = -avoid-version -rpath $(moduledir)

perl-core.c: perl-signals-list.h irssi-core.pl.h

INCLUDES = $(GLIB_CFLAGS) \
	-DSCRIPTDIR=\""$(libdir)/irssi/scripts"\" \
	-DPERL_USE_LIB=\""$(PERL_USE_LIB)"\" \
	$(PERL_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core \
	-I$(top_srcdir)/src/fe-common/core

perl_sources = \
	perl-core.c \
	perl-common.c \
	perl-signals.c \
	perl-sources.c \
	xsinit.c

perl_fe_sources = \
	module-formats.c \
	perl-fe.c

noinst_HEADERS = \
	module.h \
	module-fe.h \
	module-formats.h \
	perl-core.h \
	perl-common.h \
	perl-signals.h \
	perl-sources.h

libperl_core_la_DEPENDENCIES = .libs/libperl_orig.a .libs/DynaLoader.a

.libs/libperl_orig.a:
	if [ ! -d .libs ]; then mkdir .libs; fi
	rm -f .libs/libperl_orig.a
	if [ x$(LIBPERL_A) = x ]; then touch .libs/libperl_orig.a; else $(LN_S) $(LIBPERL_A) .libs/libperl_orig.a; fi
.libs/DynaLoader.a:
	if [ ! -d .libs ]; then mkdir .libs; fi
	rm -f .libs/DynaLoader.a
	$(LN_S) $(DYNALOADER_A) .libs/DynaLoader.a

libperl_core_la_SOURCES = \
	$(perl_sources)

libperl_core_static_la_SOURCES = \
	$(perl_sources)

libfe_perl_la_SOURCES = \
	$(perl_fe_sources)

libfe_perl_static_la_SOURCES = \
	$(perl_fe_sources)

perl-signals-list.h: $(top_srcdir)/docs/signals.txt $(srcdir)/get-signals.pl
	cat $(top_srcdir)/docs/signals.txt | $(perlpath) $(srcdir)/get-signals.pl > perl-signals-list.h

irssi-core.pl.h: irssi-core.pl
	$(top_srcdir)/file2header.sh $(srcdir)/irssi-core.pl irssi_core_code > irssi-core.pl.h

CORE_SOURCES = \
	common/Irssi.xs \
	common/Irssi.pm \
	common/Channel.xs \
	common/Core.xs \
	common/Ignore.xs \
	common/Log.xs \
	common/Masks.xs \
	common/Query.xs \
	common/Rawlog.xs \
	common/Server.xs \
	common/Settings.xs \
	common/Makefile.PL.in \
	common/typemap \
	common/module.h

IRC_SOURCES = \
	irc/Irc.xs \
	irc/Irc.pm \
	irc/Dcc.xs \
	irc/IrcChannel.xs \
	irc/IrcQuery.xs \
	irc/IrcServer.xs \
	irc/Modes.xs \
	irc/Netsplit.xs \
	irc/Notifylist.xs \
	irc/Makefile.PL.in \
	irc/typemap \
	irc/module.h

UI_SOURCES = \
	ui/UI.xs \
	ui/UI.pm \
	ui/Themes.xs \
	ui/Window.xs \
	ui/Makefile.PL.in \
	ui/typemap \
	ui/module.h

TEXTUI_SOURCES = \
	ui/TextUI.xs \
	ui/TextUI.pm \
	ui/TextBuffer.xs \
	ui/TextBufferView.xs \
	ui/Makefile.PL.in \
	ui/typemap \
	ui/module.h

EXTRA_DIST = \
	libperl_dynaloader.la \
	libperl_orig.la \
	get-signals.pl \
	irssi-core.pl \
	$(CORE_SOURCES) \
	$(IRC_SOURCES) \
	$(UI_SOURCES) \
	$(TEXTUI_SOURCES)

all-local:
	for dir in common irc ui textui; do \
	  cd $$dir && \
	  if [ ! -f Makefile ]; then \
            $(perlpath) Makefile.PL $(PERL_MM_PARAMS); \
	  fi && \
	  ($(MAKE) || $(MAKE)) && \
	  cd ..; \
	done

install-exec-local:
	for dir in common irc ui textui; do \
	  cd $$dir && $(MAKE) install && cd ..; \
	done

clean-generic:
	rm -f common/Makefile irc/Makefile ui/Makefile textui/Makefile

distclean: distclean-am
	-(cd common && $(MAKE) realclean && rm -f Makefile.PL)
	-(cd irc && $(MAKE) realclean && rm -f Makefile.PL)
	-(cd ui && $(MAKE) realclean && rm -f Makefile.PL)
	-(cd textui && $(MAKE) realclean && rm -f Makefile.PL)

libperl_core_la_LIBADD = $(PERL_LDFLAGS)
