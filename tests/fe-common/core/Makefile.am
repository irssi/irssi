include $(top_srcdir)/utils/glib-tap.mk

PACKAGE_STRING=fe-common/core

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core \
	$(GLIB_CFLAGS)

test_programs = test-formats

test_formats_CPPFLAGS = \
	-I$(top_srcdir)/src/fe-common/core \
	$(AM_CPPFLAGS)

test_formats_DEPENDENCIES = \
	../../../src/core/libcore.a \
	../../../src/lib-config/libirssi_config.a

test_formats_LDADD = \
	../../../src/fe-common/core/libfe_common_core.a \
	../../../src/core/libcore.a \
	../../../src/lib-config/libirssi_config.a \
	@PROG_LIBS@

test_formats_SOURCES = \
	test-formats.c
