/*
 module-formats.c : irssi

    Copyright (C) 2001 Timo Sirainen

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

FORMAT_REC feperl_formats[] = {
	{ MODULE_NAME, "Core", 0 },

	/* ---- */
	{ NULL, "Perl", 0 },

	{ "script_not_found", "Script {hilight $0} not found", 1, { 0 } },
	{ "script_not_loaded", "Script {hilight $0} is not loaded", 1, { 0 } },
	{ "script_loaded", "Loaded script {hilight $0}", 2, { 0, 0 } },
	{ "script_unloaded", "Unloaded script {hilight $0}", 1, { 0 } },
	{ "no_scripts_loaded", "No scripts are loaded", 0 },
	{ "script_list_header", "%#Loaded scripts:", 0 },
	{ "script_list_line", "%#$[!15]0 $1", 2, { 0, 0 } },
	{ "script_list_footer", "", 0 },
	{ "script_error", "{error Error in script {hilight $0}:}", 1, { 0 } },

	{ NULL, NULL, 0 }
};
