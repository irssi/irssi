include $(top_srcdir)/utils/glib-tap.mk

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
	../../../src/core/libcore.a \
	../../../src/lib-config/libirssi_config.a \
	@GLIB_LIBS@ \
	@OPENSSL_LIBS@

test_irc_SOURCES = \
	test-irc.c \
	../../../src/irc/core/irc-cap.c \
	../../../src/irc/core/irc-nicklist.c \
	../../../src/irc/core/irc-queries.c \
	../../../src/irc/core/irc-servers-reconnect.c \
	../../../src/irc/core/irc-servers-setup.c \
	../../../src/irc/core/irc-servers.c \
	../../../src/irc/core/irc.c \
	../../../src/irc/core/mode-lists.c \
	../../../src/irc/core/modes.c \
	../../../src/irc/core/servers-idle.c \
	../../../src/irc/core/servers-redirect.c
