if BUILD_TEXTUI
TEXTUI=fe-text
endif

if BUILD_GNOMEUI
#GNOMEUI=fe-gnome
GNOMEUI=
endif

if BUILD_IRSSIBOT
BOTUI=fe-none
endif

if HAVE_PERL
PERLDIR=perl
endif

noinst_HEADERS = \
	nls.h \
	common.h \
	common-setup.h

SUBDIRS = lib-popt lib-config core irc fe-common $(PERLDIR) $(GNOMEUI) $(TEXTUI) $(BOTUI)
