bin_PROGRAMS = irssi irssi-dummy

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	$(GLIB_CFLAGS) \
	$(CURSES_INCLUDEDIR) \
	-DLOCALEDIR=\""$(datadir)/locale"\"

IRSSIDEPS = \
	@COMMON_LIBS@ \
	@PERL_LINK_LIBS@ \
	@PERL_FE_LINK_LIBS@

irssi_DEPENDENCIES = $(IRSSIDEPS)
irssi_dummy_DEPENDENCIES = $(IRSSIDEPS)

IRSSILINK = \
	@COMMON_LIBS@ \
	@PERL_LINK_LIBS@ \
	@PERL_FE_LINK_LIBS@ \
	@PERL_LINK_FLAGS@ \
	@PROG_LIBS@

irssi_LDADD = $(IRSSILINK)
irssi_dummy_LDADD = $(IRSSILINK)

tparm_sources = \
	tparm.c

terminfo_sources = \
        term-terminfo.c \
        terminfo-core.c

curses_sources = \
	term-curses.c

if NEED_TPARM
use_tparm_sources = $(tparm_sources)
endif

if USE_CURSES
use_term_sources = $(curses_sources)
else
use_term_sources = $(terminfo_sources)
endif

irssi_dummy_SOURCES = \
        irssi-dummy.c

irssi_SOURCES = \
        gui-entry.c \
	gui-expandos.c \
        gui-printtext.c \
        gui-readline.c \
        gui-windows.c \
	lastlog.c \
        mainwindows.c \
        mainwindow-activity.c \
        mainwindows-layout.c \
        statusbar.c \
        statusbar-config.c \
        statusbar-items.c \
        term.c \
	$(use_tparm_sources) \
	$(use_term_sources) \
        textbuffer.c \
        textbuffer-commands.c \
        textbuffer-reformat.c \
        textbuffer-view.c \
        irssi.c \
	module-formats.c

noinst_HEADERS = \
        gui-entry.h \
        gui-printtext.h \
        gui-readline.h \
        gui-windows.h \
        mainwindows.h \
        statusbar.h \
        statusbar-config.h \
	term.h \
	terminfo-core.h \
        textbuffer.h \
        textbuffer-view.h \
        textbuffer-reformat.h \
	module.h \
	module-formats.h

EXTRA_DIST = \
	$(tparm_sources) \
	$(terminfo_sources) \
	$(curses_sources)
