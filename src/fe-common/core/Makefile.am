noinst_LIBRARIES = libfe_common_core.a

INCLUDES = \
	$(GLIB_CFLAGS) \
	-I$(top_srcdir)/src -I$(top_srcdir)/src/core/ \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

libfe_common_core_a_SOURCES = \
	autorun.c \
	chat-completion.c \
	command-history.c \
	completion.c \
	fe-channels.c \
	fe-common-core.c \
	fe-core-commands.c \
	fe-ignore.c \
	fe-ignore-messages.c \
	fe-log.c \
	fe-messages.c \
	fe-modules.c \
	fe-queries.c \
	fe-server.c \
	fe-settings.c \
	hilight-text.c \
	keyboard.c \
	module-formats.c \
	printtext.c \
	themes.c \
	translation.c \
	window-activity.c \
	window-commands.c \
	window-items.c \
	window-save.c \
	windows.c

noinst_HEADERS = \
	command-history.h \
	completion.h \
	fe-common-core.h \
	fe-queries.h \
	hilight-text.h \
	keyboard.h \
	module-formats.h \
	module.h \
	printtext.h \
	themes.h \
	translation.h \
	window-items.h \
	window-save.h \
	windows.h
