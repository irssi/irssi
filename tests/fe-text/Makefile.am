include $(top_srcdir)/utils/glib-tap.mk

PACKAGE_STRING=fe-text

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core \
	-I$(top_srcdir)/src/fe-common/core \
	-I$(top_srcdir)/src/fe-text \
	$(GLIB_CFLAGS)

test_programs = test-paste-join-multiline

test_paste_join_multiline_CPPFLAGS = \
	$(AM_CPPFLAGS)

# test_paste_join_multiline_DEPENDENCIES =

test_paste_join_multiline_LDADD = \
        ../../src/fe-common/core/libfe_common_core.a \
        ../../src/core/libcore.a \
        ../../src/lib-config/libirssi_config.a \
	@PROG_LIBS@ \
	@TEXTUI_LIBS@


test_paste_join_multiline_SOURCES = \
	../../src/fe-text/gui-entry.c \
	../../src/fe-text/mainwindows.c \
	../../src/fe-text/term-terminfo.c \
	../../src/fe-text/terminfo-core.c \
	../../src/fe-text/term.c \
	../../src/fe-text/textbuffer-view.c \
	../../src/fe-text/textbuffer.c \
	../../src/fe-text/gui-windows.c \
	../../src/fe-text/gui-printtext.c \
	mock-irssi.c \
	test-paste-join-multiline.c
