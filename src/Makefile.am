if BUILD_TEXTUI
TEXTUI=fe-text
endif

if BUILD_IRSSIBOT
BOTUI=fe-none
endif

if BUILD_IRSSIFUZZER
FUZZERUI=fe-fuzz
endif

if HAVE_PERL
PERLDIR=perl
endif

if HAVE_OTR
OTRDIR=otr
endif

pkginc_srcdir=$(pkgincludedir)/src
pkginc_src_HEADERS = \
	common.h

SUBDIRS = lib-config core irc fe-common $(PERLDIR) $(OTRDIR) $(TEXTUI) $(BOTUI) $(FUZZERUI)
