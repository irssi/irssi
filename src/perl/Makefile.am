moduledir = $(libdir)/irssi/modules

perl_dirs = common irc ui textui

module_LTLIBRARIES = $(perl_module_lib) $(perl_module_fe_lib)
noinst_LTLIBRARIES = $(perl_static_lib) $(perl_static_fe_lib)
EXTRA_LTLIBRARIES = \
	libperl_core.la libfe_perl.la \
	libperl_core_static.la libfe_perl_static.la

libperl_core_la_LDFLAGS = -module -avoid-version -rpath $(moduledir)
libfe_perl_la_LDFLAGS = -module -avoid-version -rpath $(moduledir)

perl-core.lo: irssi-core.pl.h
perl-signals.lo: perl-signals-list.h

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core \
	-I$(top_srcdir)/src/fe-common/core \
	$(GLIB_CFLAGS) \
	-DSCRIPTDIR=\""$(datadir)/irssi/scripts"\" \
	-DPERL_USE_LIB=\""$(PERL_USE_LIB)"\" \
	-DPERL_STATIC_LIBS=$(PERL_STATIC_LIBS) \
	$(PERL_CFLAGS)

perl_sources = \
	perl-core.c \
	perl-common.c \
	perl-signals.c \
	perl-sources.c

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

common_sources = \
	common/Irssi.xs \
	common/Irssi.pm \
	common/Channel.xs \
	common/Core.xs \
	common/Expando.xs \
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

irc_sources = \
	irc/Irc.xs \
	irc/Irc.pm \
	irc/Dcc.xs \
	irc/Channel.xs \
	irc/Ctcp.xs \
	irc/Query.xs \
	irc/Server.xs \
	irc/Modes.xs \
	irc/Netsplit.xs \
	irc/Notifylist.xs \
	irc/Client.xs \
	irc/Makefile.PL.in \
	irc/typemap \
	irc/module.h

ui_sources = \
	ui/UI.xs \
	ui/UI.pm \
	ui/Formats.xs \
	ui/Themes.xs \
	ui/Window.xs \
	ui/Makefile.PL.in \
	ui/typemap \
	ui/module.h

textui_sources = \
	textui/TextUI.xs \
	textui/TextUI.pm \
	textui/TextBuffer.xs \
	textui/TextBufferView.xs \
	textui/Statusbar.xs \
	textui/Makefile.PL.in \
	textui/typemap \
	textui/module.h

EXTRA_DIST = \
	get-signals.pl \
	irssi-core.pl \
	$(common_sources) \
	$(irc_sources) \
	$(ui_sources) \
	$(textui_sources)

all-local:
	for dir in $(perl_dirs); do \
	  cd $$dir && \
	  if [ ! -f Makefile ]; then \
	    $(perlpath) Makefile.PL $(PERL_MM_PARAMS); \
	  fi && \
	  ($(MAKE) CC="$(CC)" CCFLAGS="$(PERL_CFLAGS) $(CFLAGS)" $(PERL_EXTRA_OPTS) || \
	   $(MAKE) CC="$(CC)" CCFLAGS="$(PERL_CFLAGS) $(CFLAGS)" $(PERL_EXTRA_OPTS)) && \
	  cd ..; \
	done

install-exec-local:
	for dir in $(perl_dirs); do \
	  cd $$dir && $(MAKE) install && cd ..; \
	done

clean-generic:
	for dir in $(perl_dirs); do \
	  cd $$dir; \
	  $(MAKE) clean; \
	  cd ..; \
	done

distclean-generic:
	for dir in $(perl_dirs); do \
	  cd $$dir; \
	  $(MAKE) realclean; rm -f Makefile.PL Makefile; \
	  cd ..; \
	done

libperl_core_la_LIBADD = $(PERL_LDFLAGS)
