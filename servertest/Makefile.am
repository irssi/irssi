bin_PROGRAMS = ircserver

INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src

ircserver_LDADD = -lglib ../src/core/network.o

ircserver_SOURCES = server.c
