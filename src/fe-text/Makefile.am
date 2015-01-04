bin_PROGRAMS = irssi

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	$(GLIB_CFLAGS)

irssi_DEPENDENCIES = \
	@COMMON_LIBS@ \
	@PERL_LINK_LIBS@ \
	@PERL_FE_LINK_LIBS@ \
	@OTR_LINK_LIBS@

irssi_LDFLAGS = -export-dynamic

irssi_LDADD = \
	@COMMON_LIBS@ \
	@PERL_LINK_LIBS@ \
	@PERL_FE_LINK_LIBS@ \
	@OTR_LINK_LIBS@ \
	@OTR_LINK_FLAGS@ \
	@PERL_LINK_FLAGS@ \
	@PROG_LIBS@ \
	@TEXTUI_LIBS@

terminfo_sources = \
        term-terminfo.c \
        terminfo-core.c

use_term_sources = $(terminfo_sources)

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
	$(use_term_sources) \
        textbuffer.c \
        textbuffer-commands.c \
        textbuffer-view.c \
        irssi.c \
	module-formats.c

pkginc_fe_textdir=$(pkgincludedir)/src/fe-text
pkginc_fe_text_HEADERS = \
	statusbar-item.h

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
	module.h \
	module-formats.h

EXTRA_DIST = \
	$(terminfo_sources)
