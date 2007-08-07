ACLOCAL_AMFLAGS = -I .

# create default-config.h
config.h: default-config.h default-theme.h

default-config.h: $(srcdir)/irssi.conf
	$(srcdir)/file2header.sh $(srcdir)/irssi.conf default_config > default-config.h
default-theme.h: $(srcdir)/default.theme
	$(srcdir)/file2header.sh $(srcdir)/default.theme default_theme > default-theme.h

SUBDIRS = src docs scripts

confdir = $(sysconfdir)
conf_DATA = irssi.conf

themedir = $(datadir)/irssi/themes
theme_DATA = default.theme colorless.theme

pkginclude_HEADERS = config.h irssi-version.h

noinst_HEADERS = irssi-version.h.in

EXTRA_DIST = \
	ChangeLog \
	autogen.sh \
	curses.m4 \
	README \
	README.cygwin \
	file2header.sh \
	irssi.spec \
	irssi.spec.in \
	$(conf_DATA) \
	$(theme_DATA) \
	irssi-icon.png \
	syntax.pl \
	findsyntax.pl

## make rpms
rpm: Makefile
	$(MAKE) dist
	rpm -ta --clean $(PACKAGE)-$(VERSION).tar.gz
