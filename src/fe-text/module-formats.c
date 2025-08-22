/*
 module-formats.c : irssi

    Copyright (C) 2000 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/fe-common/core/formats.h>

FORMAT_REC gui_text_formats[] = {
	/* clang-format off */
	{ MODULE_NAME, "Text user interface", 0 },

	/* ---- */
	{ NULL, "Lastlog", 0 },

	{ "lastlog_too_long", "/LASTLOG would print $0 lines. If you really want to print all these lines use -force option.", 1, { 1 } },
	{ "lastlog_count", "{hilight Lastlog}: $0 lines", 1, { 1 } },
	{ "lastlog_start", "{hilight Lastlog}:", 0 },
	{ "lastlog_end", "{hilight End of Lastlog}", 0 },
	{ "lastlog_separator", "--", 0 },
	{ "lastlog_date", "%%F ", 0 },

	/* ---- */
	{ NULL, "Windows", 0 },

	{ "refnum_not_found", "Window number $0 not found", 1, { 0 } },
	{ "window_too_small", "Not enough room to resize this window", 0 },
	{ "cant_hide_last", "You can't hide the last window", 0 },
	{ "cant_hide_sticky_windows", "You can't hide sticky windows (use /SET autounstick_windows ON)", 0 },
	{ "cant_show_sticky_windows", "You can't show sticky windows (use /SET autounstick_windows ON)", 0 },
	{ "window_not_sticky", "Window is not sticky", 0 },
	{ "window_set_sticky", "Window set sticky", 0 },
	{ "window_unset_sticky", "Window is not sticky anymore", 0 },
	{ "window_info_sticky", "%#Sticky  : $0", 1, { 0 } },
	{ "window_info_scroll", "%#Scroll  : $0", 1, { 0 } },
	{ "window_scroll", "Window scroll mode is now $0", 1, { 0 } },
	{ "window_scroll_unknown", "Unknown scroll mode $0, must be ON, OFF or DEFAULT", 1, { 0 } },
	{ "window_hidelevel", "Window hidden level is now $0", 1, { 0 } },

	/* ---- */
	{ NULL, "Statusbars", 0 },

	{ "statusbar_list_header", "%#Name                           Type   Placement Position Visible", 0 },
	{ "statusbar_list_footer", "", 0 },
	{ "statusbar_list", "%#$[30]0 $[6]1 $[9]2 $[8]3 $4", 5, { 0, 0, 0, 1, 0 } },
	{ "statusbar_info_name", "%#Statusbar: {hilight $0}", 1, { 0 } },
	{ "statusbar_info_type", "%#Type     : $0", 1, { 0 } },
	{ "statusbar_info_placement", "%#Placement: $0", 1, { 0 } },
	{ "statusbar_info_position", "%#Position : $0", 1, { 1 } },
	{ "statusbar_info_visible", "%#Visible  : $0", 1, { 0 } },
	{ "statusbar_info_item_header", "%#Items    : Name                                Priority  Alignment", 0 },
	{ "statusbar_info_item_footer", "", 0 },
	{ "statusbar_info_item_name",  "%#         : $[35]0 $[9]1 $2", 3, { 0, 1, 0 } },
	{ "statusbar_not_found", "Statusbar doesn't exist: $0", 1, { 0 } },
	{ "statusbar_not_found", "Statusbar is disabled: $0", 1, { 0 } },
	{ "statusbar_item_not_found", "Statusbar item doesn't exist: $0", 1, { 0 } },
	{ "statusbar_unknown_command", "Unknown statusbar command: $0", 1, { 0 } },
	{ "statusbar_unknown_type", "Statusbar type must be 'window' or 'root'", 1, { 0 } },
	{ "statusbar_unknown_placement", "Statusbar placement must be 'top' or 'bottom'", 1, { 0 } },
	{ "statusbar_unknown_visibility", "Statusbar visibility must be 'always', 'active' or 'inactive'", 1, { 0 } },

	/* ---- */
	{ NULL, "Pasting", 0 },

	{ "paste_warning", "Pasting $0 lines to $1. Press Ctrl-K if you wish to do this or Ctrl-C to cancel. Ctrl-P to print the paste content, Ctrl-E to insert the paste in the input line, Ctrl-U to pass the paste to a signal handler.", 2, { 1, 0 } },
	{ "paste_prompt", "Hit Ctrl-K to paste, Ctrl-C to abort?", 0 },
	{ "paste_content", "%_>%_ $0", 1, { 0 } },

	/* ---- */
	{ NULL, "Welcome", 0 },

	{ "irssi_banner",
	  " ___           _%:"
	  "|_ _|_ _ _____(_)%:"
	  " | || '_(_-<_-< |%:"
	  "|___|_| /__/__/_|%:"
	  "Irssi v$J - https://irssi.org", 0 },
	{ "welcome_firsttime",
	  "- - - - - - - - - - - - - - - - - - - - - - - - - - - -\n"
	  "Hi there! If this is your first time using Irssi, you%:"
	  "might want to go to our website and read the startup%:"
	  "documentation to get you going.%:%:"
	  "Our community and staff are available to assist you or%:"
	  "to answer any questions you may have.%:%:"
	  "Use the /HELP command to get detailed information about%:"
	  "the available commands.%:"
	  "- - - - - - - - - - - - - - - - - - - - - - - - - - - -", 0 },
	{ "welcome_init_settings", "The following settings were initialized", 0 },

	/* ---- */
	{ NULL, "Sidepanels", 0 },
	{ "sidepanel_header", "%K$0", 1, { 0 } },
	{ "sidepanel_item", "$0", 1, { 0 } },
	{ "sidepanel_item_selected", "%U$0%U", 1, { 0 } },
	{ "sidepanel_item_nick_mention", "%M$0", 1, { 0 } },
	{ "sidepanel_item_query_msg", "%M$0", 1, { 0 } },
	{ "sidepanel_item_activity", "%y$0", 1, { 0 } },
	{ "sidepanel_item_events", "%g$0", 1, { 0 } },
	{ "sidepanel_item_highlight", "%R$0", 1, { 0 } },
	{ "sidepanel_nick_op", "%Y$0", 1, { 0 } },
	{ "sidepanel_nick_voice", "%C$0", 1, { 0 } },
	{ "sidepanel_nick_normal", "$0", 1, { 0 } },
	{ "sidepanel_nick_op_status", "%Y$0%n$1", 2, { 0, 0 } },
	{ "sidepanel_nick_voice_status", "%C$0%n$1", 2, { 0, 0 } },
	{ "sidepanel_nick_normal_status", "$0$1", 2, { 0, 0 } },

	{ NULL, NULL, 0 }
	/* clang-format on */
};
