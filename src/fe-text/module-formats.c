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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "formats.h"

FORMAT_REC gui_text_formats[] =
{
	{ MODULE_NAME, "Text user interface", 0 },

	{ "lastlog_too_long", "/LASTLOG would print $0 lines. If you really want to print all these lines use -force option.", 1, { 1 } },
	{ "lastlog_count", "{hilight Lastlog}: $0 lines", 1, { 1 } },
	{ "lastlog_start", "{hilight Lastlog}:", 0 },
	{ "lastlog_end", "{hilight End of Lastlog}", 0 },
	{ "lastlog_separator", "--", 0 },

	{ "refnum_not_found", "Window number $0 not found", 1, { 0 } },
	{ "window_too_small", "Not enough room to resize this window", 0 },
	{ "cant_hide_last", "You can't hide the last window", 0 },
	{ "cant_hide_sticky_windows", "You can't hide sticky windows (use /WINDOW STICK OFF)", 0 },
	{ "cant_show_sticky_windows", "You can't show sticky windows (use /WINDOW STICK OFF)", 0 },
	{ "window_not_sticky", "Window is not sticky", 0 },
	{ "window_set_sticky", "Window set sticky", 0 },
	{ "window_unset_sticky", "Window is not sticky anymore", 0 },
	{ "window_info_sticky", "Sticky  : $0", 1, { 0 } },
	{ "window_scroll", "Window scroll mode is now $0", 1, { 0 } },
	{ "window_scroll_unknown", "Unknown scroll mode $0, must be ON, OFF or DEFAULT", 1, { 0 } },

	{ NULL, NULL, 0 }
};
