if BUILD_TEXTUI
TEXTUI=gui-text
endif

if BUILD_GNOMEUI
GNOMEUI=gui-gnome
endif

if BUILD_IRSSIBOT
BOTUI=gui-none
endif

noinst_HEADERS = \
	nls.h \
	common.h \
	common-setup.h \
	irssi-plugin.h \
	irssi-plugin-gui.h

SUBDIRS = lib-popt lib-config irc-base irc-extra ui-common $(GNOMEUI) $(TEXTUI) $(BOTUI)
