bin_PROGRAMS = irssi-fuzz

# Force link with clang++ for libfuzzer support
CCLD=clang++ $(CXXFLAGS)

AM_CPPFLAGS = \
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
	$(top_srcdir)/src/fe-text/module-formats.c

noinst_HEADERS = \
	$(top_srcdir)/src/fe-text/module-formats.h
