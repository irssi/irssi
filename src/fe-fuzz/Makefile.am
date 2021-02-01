SUBDIRS = irc fe-common

bin_PROGRAMS = irssi-fuzz server-fuzz

# Force link with CXX for libfuzzer support
CCLD=$(CXX) $(CXXFLAGS)

AM_CPPFLAGS = \
	-I$(top_builddir) \
	$(GLIB_CFLAGS)

irssi_fuzz_DEPENDENCIES = @COMMON_LIBS@

irssi_fuzz_LDADD = \
	@COMMON_LIBS@ \
	@PROG_LIBS@ \
	$(FUZZER_LIBS)

irssi_fuzz_SOURCES = \
        irssi.c \
        null-logger.c \
	../fe-text/module-formats.c

server_fuzz_DEPENDENCIES = @COMMON_LIBS@

server_fuzz_LDADD = \
	@COMMON_LIBS@ \
	@PROG_LIBS@ \
	$(FUZZER_LIBS)

server_fuzz_SOURCES = \
	server.c \
        null-logger.c \
	../fe-text/module-formats.c

noinst_HEADERS = \
        null-logger.h \
	../fe-text/module-formats.h

EXTRA_DIST = meson.build
