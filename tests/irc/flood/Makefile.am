include $(top_srcdir)/utils/glib-tap.mk

PACKAGE_STRING=irc/flood

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	$(GLIB_CFLAGS)

test_programs = \
	test-796

test_796_CPPFLAGS = \
	-I$(top_srcdir)/src/fe-common/core \
	-I$(top_srcdir)/src/irc/core \
	-I$(top_srcdir)/src/irc/flood \
	$(AM_CPPFLAGS)

test_796_DEPENDENCIES = \
	../../../src/core/libcore.a \
	../../../src/lib-config/libirssi_config.a

test_796_LDADD = \
	../../../src/irc/libirc.a \
	../../../src/fe-common/irc/libfe_common_irc.a \
	../../../src/fe-common/irc/dcc/libfe_irc_dcc.a \
	../../../src/fe-common/irc/notifylist/libfe_irc_notifylist.a \
	../../../src/irc/dcc/libirc_dcc.a \
	../../../src/irc/notifylist/libirc_notifylist.a \
	../../../src/irc/flood/libirc_flood.a \
	../../../src/irc/core/libirc_core.a \
	../../../src/fe-common/core/libfe_common_core.a \
	../../../src/core/libcore.a \
	../../../src/lib-config/libirssi_config.a \
	@PROG_LIBS@

test_796_SOURCES = \
	test-796.c
