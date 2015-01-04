/*
 * Off-the-Record Messaging (OTR) module for the irssi IRC client
 *
 * Copyright (C) 2008 - Uli Meis <a.sporto+bee@gmail.com>
 *               2012 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef IRSSI_IRSSI_OTR_H
#define IRSSI_IRSSI_OTR_H

/* Ease our life a bit. */
#define OTR_IRSSI_MSG_PREFIX	"%9OTR%9: "

/*
 * Irssi macros for printing text to console.
 */
#define IRSSI_OTR_DEBUG(fmt, ...) \
	do {                                                                    \
		if (debug) {                                                        \
			printtext(NULL, NULL, MSGLEVEL_MSGS, OTR_IRSSI_MSG_PREFIX fmt,  \
						## __VA_ARGS__);                                    \
		}                                                                   \
	} while (0)

#endif /* IRSSI_IRSSI_OTR_H */
