#ifndef IRSSI_FE_TEXT_MODULE_FORMATS_H
#define IRSSI_FE_TEXT_MODULE_FORMATS_H

#include <irssi/src/fe-common/core/formats.h>

/* This mirrors indices in module-formats.c order; keep in sync if changed. */

enum {
	TXT_MODULE_NAME = 0,

	TXT_FILL_1,

	TXT_LASTLOG_TOO_LONG,
	TXT_LASTLOG_COUNT,
	TXT_LASTLOG_START,
	TXT_LASTLOG_END,
	TXT_LASTLOG_SEPARATOR,
	TXT_LASTLOG_DATE,

	TXT_FILL_2,

	TXT_REFNUM_NOT_FOUND,
	TXT_WINDOW_TOO_SMALL,
	TXT_CANT_HIDE_LAST,
	TXT_CANT_HIDE_STICKY_WINDOWS,
	TXT_CANT_SHOW_STICKY_WINDOWS,
	TXT_WINDOW_NOT_STICKY,
	TXT_WINDOW_SET_STICKY,
	TXT_WINDOW_UNSET_STICKY,
	TXT_WINDOW_INFO_STICKY,
	TXT_WINDOW_INFO_SCROLL,
	TXT_WINDOW_SCROLL,
	TXT_WINDOW_SCROLL_UNKNOWN,
	TXT_WINDOW_HIDELEVEL,

	TXT_FILL_3,

	TXT_STATUSBAR_LIST_HEADER,
	TXT_STATUSBAR_LIST_FOOTER,
	TXT_STATUSBAR_LIST,
	TXT_STATUSBAR_INFO_NAME,
	TXT_STATUSBAR_INFO_TYPE,
	TXT_STATUSBAR_INFO_PLACEMENT,
	TXT_STATUSBAR_INFO_POSITION,
	TXT_STATUSBAR_INFO_VISIBLE,
	TXT_STATUSBAR_INFO_ITEM_HEADER,
	TXT_STATUSBAR_INFO_ITEM_FOOTER,
	TXT_STATUSBAR_INFO_ITEM_NAME,
	TXT_STATUSBAR_NOT_FOUND,
	TXT_STATUSBAR_NOT_ENABLED,
	TXT_STATUSBAR_ITEM_NOT_FOUND,
	TXT_STATUSBAR_UNKNOWN_COMMAND,
	TXT_STATUSBAR_UNKNOWN_TYPE,
	TXT_STATUSBAR_UNKNOWN_PLACEMENT,
	TXT_STATUSBAR_UNKNOWN_VISIBILITY,

	TXT_FILL_4,

	TXT_PASTE_WARNING,
	TXT_PASTE_PROMPT,
	TXT_PASTE_CONTENT,

	TXT_FILL_5, /* Welcome */

	TXT_IRSSI_BANNER,
	TXT_WELCOME_FIRSTTIME,
	TXT_WELCOME_INIT_SETTINGS,

	TXT_COUNT
};

/* Sidepanel format indices appended at the end of gui_text_formats: we declare explicit macros. */
#define TXT_SIDEPANEL_HEADER format_find_tag(MODULE_NAME, "sidepanel_header")
#define TXT_SIDEPANEL_ITEM format_find_tag(MODULE_NAME, "sidepanel_item")
#define TXT_SIDEPANEL_ITEM_SELECTED format_find_tag(MODULE_NAME, "sidepanel_item_selected")
#define TXT_SIDEPANEL_ITEM_ACTIVITY format_find_tag(MODULE_NAME, "sidepanel_item_activity")
#define TXT_SIDEPANEL_ITEM_NICK_MENTION format_find_tag(MODULE_NAME, "sidepanel_item_nick_mention")
#define TXT_SIDEPANEL_ITEM_QUERY_MSG format_find_tag(MODULE_NAME, "sidepanel_item_query_msg")
#define TXT_SIDEPANEL_ITEM_EVENTS format_find_tag(MODULE_NAME, "sidepanel_item_events")
#define TXT_SIDEPANEL_ITEM_HIGHLIGHT format_find_tag(MODULE_NAME, "sidepanel_item_highlight")
#define TXT_SIDEPANEL_NICK_OP format_find_tag(MODULE_NAME, "sidepanel_nick_op")
#define TXT_SIDEPANEL_NICK_VOICE format_find_tag(MODULE_NAME, "sidepanel_nick_voice")
#define TXT_SIDEPANEL_NICK_NORMAL format_find_tag(MODULE_NAME, "sidepanel_nick_normal")
#define TXT_SIDEPANEL_NICK_OP_STATUS format_find_tag(MODULE_NAME, "sidepanel_nick_op_status")
#define TXT_SIDEPANEL_NICK_VOICE_STATUS format_find_tag(MODULE_NAME, "sidepanel_nick_voice_status")
#define TXT_SIDEPANEL_NICK_NORMAL_STATUS                                                           \
	format_find_tag(MODULE_NAME, "sidepanel_nick_normal_status")

extern FORMAT_REC gui_text_formats[TXT_COUNT + 1];

#endif
