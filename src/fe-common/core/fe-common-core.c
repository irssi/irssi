/*
 fe-common-core.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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
#include "module-formats.h"
#include "levels.h"
#include "settings.h"

#include "hilight-text.h"
#include "command-history.h"
#include "completion.h"
#include "keyboard.h"
#include "printtext.h"
#include "themes.h"
#include "translation.h"
#include "windows.h"
#include "window-items.h"

#include <sys/signal.h>

void autorun_init(void);
void autorun_deinit(void);

void fe_core_log_init(void);
void fe_core_log_deinit(void);

void fe_log_init(void);
void fe_log_deinit(void);

void fe_modules_init(void);
void fe_modules_deinit(void);

void fe_server_init(void);
void fe_server_deinit(void);

void fe_settings_init(void);
void fe_settings_deinit(void);

void window_activity_init(void);
void window_activity_deinit(void);

void window_commands_init(void);
void window_commands_deinit(void);

void fe_core_commands_init(void);
void fe_core_commands_deinit(void);

void fe_common_core_init(void)
{
	/*settings_add_bool("lookandfeel", "show_menubar", TRUE);
	settings_add_bool("lookandfeel", "show_toolbar", FALSE);
	settings_add_bool("lookandfeel", "show_statusbar", TRUE);
	settings_add_bool("lookandfeel", "show_nicklist", TRUE);*/
	settings_add_bool("lookandfeel", "timestamps", TRUE);
	settings_add_bool("lookandfeel", "msgs_timestamps", FALSE);
	settings_add_bool("lookandfeel", "hide_text_style", FALSE);
	settings_add_bool("lookandfeel", "bell_beeps", FALSE);
	settings_add_bool("lookandfeel", "show_nickmode", TRUE);

	settings_add_bool("lookandfeel", "use_status_window", TRUE);
	settings_add_bool("lookandfeel", "use_msgs_window", FALSE);
	/*settings_add_bool("lookandfeel", "autoraise_msgs_window", FALSE);*/
	/*settings_add_bool("lookandfeel", "use_tabbed_windows", TRUE);
	settings_add_int("lookandfeel", "tab_orientation", 3);*/
	settings_add_str("lookandfeel", "current_theme", "default");

	themes_init();
        theme_register(fecommon_core_formats);

	autorun_init();
	hilight_text_init();
	command_history_init();
	completion_init();
	keyboard_init();
	printtext_init();
	fe_log_init();
	fe_modules_init();
	fe_server_init();
	fe_settings_init();
	translation_init();
	windows_init();
	window_activity_init();
	window_commands_init();
	window_items_init();
	fe_core_commands_init();
}

void fe_common_core_deinit(void)
{
	autorun_deinit();
	hilight_text_deinit();
	command_history_deinit();
	completion_deinit();
	keyboard_deinit();
	printtext_deinit();
	fe_log_deinit();
	fe_modules_deinit();
	fe_server_deinit();
	fe_settings_deinit();
	translation_deinit();
	windows_deinit();
	window_activity_deinit();
	window_commands_deinit();
	window_items_deinit();
	fe_core_commands_deinit();

        theme_unregister();
	themes_deinit();
}

void fe_common_core_finish_init(void)
{
	WINDOW_REC *window;

	signal(SIGPIPE, SIG_IGN);

	if (settings_get_bool("use_status_window")) {
		window = window_create(NULL, TRUE);
		window_set_name(window, "(status)");
		window_set_level(window, MSGLEVEL_ALL ^
				 (settings_get_bool("use_msgs_window") ?
				  (MSGLEVEL_MSGS|MSGLEVEL_ACTIONS) : 0));
	}

	if (settings_get_bool("use_msgs_window")) {
		window = window_create(NULL, TRUE);
		window_set_name(window, "(msgs)");
		window_set_level(window, MSGLEVEL_MSGS|MSGLEVEL_ACTIONS);
	}

	if (windows == NULL) {
		/* we have to have at least one window.. */
                window = window_create(NULL, TRUE);
	}
}
