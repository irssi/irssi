bin_PROGRAMS = ircserver

INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src

if BUILD_MEMDEBUG
memdebug_src=../src/irc-base/memdebug.o
else
memdebug_src=
endif

ircserver_LDADD = -lglib ../src/irc-base/network.o $(memdebug_src)

ircserver_SOURCES = server.c
