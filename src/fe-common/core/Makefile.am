noinst_LIBRARIES = libfe_common_core.a

AM_CPPFLAGS = \
	-I$(top_builddir) \
	-I$(top_srcdir)/src -I$(top_srcdir)/src/core/ \
	$(GLIB_CFLAGS) \
	-DHELPDIR=\""$(datadir)/irssi/help"\" \
	-DTHEMESDIR=\""$(datadir)/irssi/themes"\"

libfe_common_core_a_SOURCES = \
	chat-completion.c \
	command-history.c \
	completion.c \
	fe-channels.c \
	fe-common-core.c \
	fe-core-commands.c \
	fe-exec.c \
	fe-expandos.c \
	fe-help.c \
	fe-ignore.c \
	fe-ignore-messages.c \
	fe-log.c \
	fe-messages.c \
	fe-modules.c \
	fe-queries.c \
	fe-server.c \
	fe-settings.c \
	fe-tls.c \
	formats.c \
	hilight-text.c \
	keyboard.c \
	module-formats.c \
	printtext.c \
	fe-recode.c \
	themes.c \
	window-activity.c \
	window-commands.c \
	window-items.c \
	windows-layout.c \
	fe-windows.c

if HAVE_CAPSICUM
libfe_common_core_a_SOURCES += \
	fe-capsicum.c
endif

pkginc_fe_common_coredir=$(pkgincludedir)/src/fe-common/core
pkginc_fe_common_core_HEADERS = \
	command-history.h \
	chat-completion.h \
	completion.h \
	fe-capsicum.h \
	fe-channels.h \
	fe-common-core.h \
	fe-core-commands.h \
	fe-exec.h \
	fe-messages.h \
	fe-queries.h \
	fe-settings.h \
	fe-tls.h \
	formats.h \
	hilight-text.h \
	keyboard.h \
	module-formats.h \
	module.h \
	printtext.h \
	fe-recode.h \
	themes.h \
	window-activity.h \
	window-items.h \
	windows-layout.h \
	fe-windows.h
