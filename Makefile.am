# create default-config.h
config.h: default-config.h

default-config.h: $(srcdir)/config
	$(srcdir)/file2header.sh $(srcdir)/config > default-config.h

if BUILD_PLUGINS
PLUGINS=plugins
endif
if BUILD_SERVERTEST
SERVERTEST=servertest
endif

SUBDIRS = po intl src $(SERVERTEST) docs scripts

confdir = $(sysconfdir)/irssi
conf_DATA = config colorless.theme split.theme

noinst_HEADERS = irssi-version.h

EXTRA_DIST = \
	ChangeLog \
	autogen.sh \
	curses.m4 \
	README \
	file2header.sh \
	irssi.spec \
	irssi.spec.in \
	$(conf_DATA) \
	irssi-config.in \
	irssi-icon.png

## make rpms
rpm: Makefile
	$(MAKE) dist
	rpm -ta --clean $(PACKAGE)-$(VERSION).tar.gz
