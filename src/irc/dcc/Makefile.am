noinst_LIBRARIES = libirc_dcc.a

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	$(GLIB_CFLAGS)

libirc_dcc_a_SOURCES = \
	dcc.c \
	dcc-chat.c \
	dcc-get.c \
	dcc-send.c \
	dcc-resume.c \
	dcc-autoget.c \
	dcc-queue.c \
	dcc-server.c

pkginc_irc_dccdir=$(pkgincludedir)/src/irc/dcc
pkginc_irc_dcc_HEADERS = \
	dcc-rec.h \
	dcc-file-rec.h \
	dcc.h \
	dcc-file.h \
	dcc-chat.h \
	dcc-get.h \
	dcc-send.h \
	dcc-queue.h \
	module.h \
	dcc-server.h
