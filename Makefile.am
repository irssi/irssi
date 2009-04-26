ACLOCAL_AMFLAGS = -I .

# create default-config.h
BUILT_SOURCES = default-config.h default-theme.h irssi-version.h

.PHONY: irssi-version.h

default-config.h: $(srcdir)/irssi.conf
	$(srcdir)/file2header.sh $(srcdir)/irssi.conf default_config > default-config.h
default-theme.h: $(srcdir)/default.theme
	$(srcdir)/file2header.sh $(srcdir)/default.theme default_theme > default-theme.h
irssi-version.h:
	$(srcdir)/irssi-version.sh $(srcdir) | cmp -s - $@ || $(srcdir)/irssi-version.sh $(srcdir) >$@

SUBDIRS = src docs scripts

confdir = $(sysconfdir)
conf_DATA = irssi.conf

themedir = $(datadir)/irssi/themes
theme_DATA = default.theme colorless.theme

pkginclude_HEADERS = irssi-config.h irssi-version.h

EXTRA_DIST = \
	ChangeLog \
	autogen.sh \
	curses.m4 \
	README \
	file2header.sh \
	$(conf_DATA) \
	$(theme_DATA) \
	irssi-config.in \
	irssi-icon.png \
	irssi-version.sh \
	syntax.pl
