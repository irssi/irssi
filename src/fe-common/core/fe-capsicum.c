/*
 fe-capsicum.c : irssi

    Copyright (C) 2017 Edward Tomasz Napierala <trasz@FreeBSD.org>

    This software was developed by SRI International and the University of
    Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
    ("CTSRD"), as part of the DARPA CRASH research programme.

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
#include <irssi/src/fe-common/core/fe-capsicum.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/fe-common/core/module-formats.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/core/signals.h>

static void capability_mode_enabled(void)
{

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_CAPSICUM_ENABLED);
}

static void capability_mode_disabled(void)
{

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_CAPSICUM_DISABLED);
}

static void capability_mode_failed(gchar *msg)
{

	printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_CAPSICUM_FAILED, msg);
}

void fe_capsicum_init(void)
{

	signal_add("capability mode enabled", (SIGNAL_FUNC) capability_mode_enabled);
	signal_add("capability mode disabled", (SIGNAL_FUNC) capability_mode_disabled);
	signal_add("capability mode failed", (SIGNAL_FUNC) capability_mode_failed);
}

void fe_capsicum_deinit(void)
{
	signal_remove("capability mode enabled", (SIGNAL_FUNC) capability_mode_enabled);
	signal_remove("capability mode disabled", (SIGNAL_FUNC) capability_mode_disabled);
	signal_remove("capability mode failed", (SIGNAL_FUNC) capability_mode_failed);
}
