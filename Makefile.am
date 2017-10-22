ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

# create default-config.h
BUILT_SOURCES = default-config.h default-theme.h irssi-version.h
CLEANFILES = default-config.h default-theme.h

@MAINTAINER_MODE_TRUE@.PHONY: irssi-version.h

default-config.h: $(srcdir)/irssi.conf
	$(srcdir)/utils/file2header.sh $(srcdir)/irssi.conf default_config > default-config.h

default-theme.h: $(srcdir)/themes/default.theme
	$(srcdir)/utils/file2header.sh $(srcdir)/themes/default.theme default_theme > default-theme.h

irssi-version.h:
	VERSION="$(VERSION)" $(srcdir)/utils/irssi-version.sh $(srcdir) | \
		cmp -s - $@ || VERSION="$(VERSION)" $(srcdir)/utils/irssi-version.sh $(srcdir) >$@

SUBDIRS = src tests docs scripts themes utils

confdir = $(sysconfdir)
conf_DATA = irssi.conf

pkginclude_HEADERS = irssi-config.h irssi-version.h

EXTRA_DIST = \
	ChangeLog \
	autogen.sh \
	README.md \
	$(conf_DATA) \
	irssi-config.in \
	irssi-icon.png
