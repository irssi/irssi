moduledir = $(libdir)/irssi/modules

module_LTLIBRARIES = $(otr_module_lib)
noinst_LTLIBRARIES = $(otr_static_lib)

EXTRA_LTLIBRARIES = \
	libotr_core.la \
	libotr_core_static.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	$(GLIB_CFLAGS) \
	$(OTR_CFLAGS)

libotr_core_la_LDFLAGS = -module -avoid-version -rpath $(moduledir)
libotr_core_la_LIBADD = $(OTR_LDFLAGS)

otr_sources = \
	key.c \
	module.c \
	otr-formats.c \
	otr-ops.c \
	otr-fe.c \
	otr.c

libotr_core_la_SOURCES = \
	$(otr_sources)

libotr_core_static_la_SOURCES = \
	$(otr_sources)

noinst_HEADERS = \
	irssi-otr.h \
	key.h \
	module.h \
	otr-formats.h \
	otr-fe.h \
	otr.h
