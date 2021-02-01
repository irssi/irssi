include $(top_srcdir)/utils/glib-tap.mk

PACKAGE_STRING=irc/core

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	$(GLIB_CFLAGS)

test_programs = test-channel-events test-irc

CPPFLAGS = \
	$(AM_CPPFLAGS)

DEPENDENCIES = \
	../../../src/core/libcore.a \
	../../../src/lib-config/libirssi_config.a

LDADD = \
	../../../src/irc/core/libirc_core.a \
	../../../src/core/libcore.a \
	../../../src/lib-config/libirssi_config.a \
	@PROG_LIBS@

test_channel_events_SOURCES = \
	test-channel-events.c

test_irc_SOURCES = \
	test-irc.c

EXTRA_DIST += meson.build
