if BUILD_TEXTUI
TEXTUI=fe-text
endif

if BUILD_GNOMEUI
GNOMEUI=fe-gnome
endif

if BUILD_IRSSIBOT
BOTUI=fe-none
endif

noinst_HEADERS = \
	nls.h \
	common.h \
	common-setup.h \
	irssi-plugin.h \
	irssi-plugin-gui.h

SUBDIRS = lib-popt lib-config core irc fe-common perl $(GNOMEUI) $(TEXTUI) $(BOTUI)
