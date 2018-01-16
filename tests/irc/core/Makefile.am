include $(top_srcdir)/utils/glib-tap.mk

PACKAGE_STRING=irc/core

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	$(GLIB_CFLAGS)

test_programs = test-irc

test_irc_CPPFLAGS = \
	-I$(top_srcdir)/src/irc/core \
	$(AM_CPPFLAGS)

test_irc_DEPENDENCIES = \
	../../../src/core/libcore.a \
	../../../src/lib-config/libirssi_config.a

test_irc_LDADD = \
	../../../src/irc/core/libirc_core.a \
	../../../src/core/libcore.a \
	../../../src/lib-config/libirssi_config.a \
	@PROG_LIBS@

test_irc_SOURCES = \
	test-irc.c
