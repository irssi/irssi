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

SUBDIRS = po intl macros src $(PLUGINS) $(SERVERTEST) docs scripts

## to automatically rebuild aclocal.m4 if any of the macros in
## `macros/' change
@MAINT@include macros/macros.dep
@MAINT@macros/macros.dep: $(srcdir)/macros/Makefile.am
@MAINT@	cd macros && $(MAKE) macros.dep

if HAVE_GNOME
desktopdir = $(datadir)/gnome/apps/Internet
desktop_DATA = irssi.desktop

corbadir = $(sysconfdir)/CORBA/servers
corba_DATA = irssi.gnorba
endif

confdir = $(sysconfdir)/irssi
conf_DATA = config colorless.theme split.theme

noinst_HEADERS = irssi-version.h

EXTRA_DIST = \
	autogen.sh \
	README \
	README-HEBREW \
	file2header.sh \
	irssi.spec \
	$(conf_DATA) \
	irssi.gnorba \
	irssi.desktop

## make rpms
rpm: Makefile
	$(MAKE) dist
	rpm -ta --clean $(PACKAGE)-$(VERSION).tar.gz
