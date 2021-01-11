if BUILD_IRSSIPROXY
PROXY=proxy
endif

SUBDIRS = core dcc flood notifylist $(PROXY)

noinst_LIBRARIES = libirc.a

libirc_a_SOURCES = irc.c

EXTRA_DIST = meson.build
