bin_PROGRAMS = irssi-text

INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	-I$(top_srcdir)/src/fe-common/irc/ \
	$(CURSES_INCLUDEDIR)

irssi_text_DEPENDENCIES = @COMMON_LIBS@

irssi_text_LDADD = \
	@COMMON_LIBS@ \
        $(PROG_LIBS) \
        $(CURSES_LIBS) \
	$(INTLLIBS) \
	$(PERL_LDFLAGS)

irssi_text_SOURCES = \
        gui-entry.c \
        gui-mainwindows.c \
        gui-printtext.c \
        gui-readline.c \
	gui-special-vars.c \
        gui-statusbar.c \
        gui-statusbar-items.c \
        gui-textwidget.c \
        gui-windows.c \
        irssi.c \
	module-formats.c \
        screen.c

noinst_HEADERS = \
        gui-entry.h \
        gui-mainwindows.h \
        gui-printtext.h \
        gui-readline.h \
	gui-special-vars.h \
        gui-statusbar.h \
        gui-statusbar-items.h \
        gui-textwidget.h \
        gui-windows.h \
	module-formats.h \
        screen.h
