/*
    fe-sasl.c : irssi

    Copyright (C) 2015 The Lemon Man

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

#ifndef __SASL_H
#define __SASL_H

void sasl_mechanism_register(const char *);
void sasl_mechanism_unregister(const char *);
void sasl_send_response(IRC_SERVER_REC *, GBytes *);
void sasl_abort(IRC_SERVER_REC *);

void sasl_init(void);
void sasl_deinit(void);

#endif
