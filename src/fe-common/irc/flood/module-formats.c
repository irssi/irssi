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

FORMAT_REC fecommon_irc_flood_formats[] =
{
	{ MODULE_NAME, "Flood", 0 },

	/* ---- */
	{ NULL, "Autoignore", 0 },

	{ "autoignore", "Flood detected from {nick $0}, autoignoring for {hilight $1} minutes", 2, { 0, 1 } },
	{ "autounignore", "Removed autoignore from {nick $0}", 1, { 0 } },

	{ NULL, NULL, 0 }
};
