bin_PROGRAMS = ircserver

INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src

ircserver_LDADD = $(GLIB_LIBS) ../src/core/network.o

ircserver_SOURCES = server.c
