if BUILD_TEXTUI
TEXTUI=fe-text
endif

if BUILD_IRSSIBOT
BOTUI=fe-none
endif

if HAVE_PERL
PERLDIR=perl
endif

pkginc_srcdir=$(pkgincludedir)/src
pkginc_src_HEADERS = \
	common.h

SUBDIRS = lib-popt lib-config core irc fe-common $(PERLDIR) $(TEXTUI) $(BOTUI)
