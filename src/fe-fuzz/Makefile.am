SUBDIRS = irc fe-common

bin_PROGRAMS = irssi-fuzz server-fuzz

# Force link with CXX for libfuzzer support
CCLD=$(CXX) $(CXXFLAGS)

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	$(GLIB_CFLAGS)

irssi_fuzz_DEPENDENCIES = @COMMON_LIBS@

irssi_fuzz_LDADD = \
	@COMMON_LIBS@ \
	@PROG_LIBS@ \
	$(FUZZER_LIBS)

irssi_fuzz_SOURCES = \
        irssi.c \
	../fe-text/module-formats.c

server_fuzz_DEPENDENCIES = @COMMON_LIBS@

server_fuzz_LDADD = \
	@COMMON_LIBS@ \
	@PROG_LIBS@ \
	$(FUZZER_LIBS)

server_fuzz_SOURCES = \
	server.c \
	../fe-text/module-formats.c

noinst_HEADERS = \
	../fe-text/module-formats.h
