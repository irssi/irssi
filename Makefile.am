# create default-config.h
config.h: default-config.h

default-config.h: $(srcdir)/config
	$(srcdir)/file2header.sh $(srcdir)/config > default-config.h

## if <internationalization support>
#SUBDIRS = po intl macros support # <your subdirs here>
## else
if BUILD_PLUGINS
PLUGINS=plugins
endif
if BUILD_SERVERTEST
SERVERTEST=servertest
endif

SUBDIRS = macros src $(PLUGINS) $(SERVERTEST)
## endif

## to automatically rebuild aclocal.m4 if any of the macros in
## `macros/' change
@MAINT@include $(srcdir)/macros/macros.dep
@MAINT@macros/macros.dep: $(srcdir)/macros/Makefile.am
@MAINT@	cd $(srcdir)/macros && $(MAKE) macros.dep

if HAVE_GNOME
appletdir = $(datadir)/applets/Network
applet_DATA = irssi.desktop

corbadir = $(sysconfdir)/CORBA/servers
corba_DATA = irssi.gnorba
endif

confdir = $(sysconfdir)/irssi
conf_DATA = config colorless.theme

EXTRA_DIST = window-views-patch.diff \
	autogen.sh \
	README-HEBREW \
	COMMANDS \
	file2header.sh \
	irssi.spec \
	$(conf_DATA) \
	irssi.gnorba \
	irssi.desktop

## make rpms
rpm: Makefile
	$(MAKE) dist
	rpm -ta --clean $(PACKAGE)-$(VERSION).tar.gz
