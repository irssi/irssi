/*
 wcwidth-wrapper.c : irssi

    Copyright (C) 2018 dequis

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

#define _GNU_SOURCE
#include <wchar.h>

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/utf8.h>

#ifdef HAVE_LIBUTF8PROC
#include <utf8proc.h>
#endif

/* wcwidth=2 since unicode 5.2.0 */
#define UNICODE_SQUARE_HIRAGANA_HOKA 0x1F200

/* wcwidth=2 since unicode 9.0.0 */
#define UNICODE_IRSSI_LOGO 0x1F525

enum {
	WCWIDTH_IMPL_OLD,
	WCWIDTH_IMPL_SYSTEM
#ifdef HAVE_LIBUTF8PROC
	,WCWIDTH_IMPL_JULIA
#endif
};

WCWIDTH_FUNC wcwidth_impl_func = mk_wcwidth;

int i_wcwidth(unichar ucs)
{
	return (*wcwidth_impl_func)(ucs);
}

static int system_wcwidth(unichar ucs)
{
	int retval = wcwidth((wchar_t) ucs);

	if (retval < 0) {
		/* Treat all unknown characters as taking one cell. This is
		 * the reason mk_wcwidth and other outdated implementations
		 * mostly worked with newer unicode, while glibc's wcwidth
		 * needs updating to recognize new characters.
		 *
		 * Instead of relying on that, we keep the behavior of assuming
		 * one cell even for glibc's implementation, which is still
		 * highly accurate and less of a headache overall.
		 */
		return 1;
	}

	return retval;
}

#ifdef HAVE_LIBUTF8PROC
/* wrapper because the function signatures are different
 * (the parameter is unsigned for us, signed for them) */
static int julia_wcwidth(unichar ucs)
{
	return utf8proc_charwidth(ucs);
}
#endif

static void read_settings(void)
{
	static int choice = -1;
	int newchoice;

	newchoice = settings_get_choice("wcwidth_implementation");

	if (choice == newchoice) {
		return;
	}

	choice = newchoice;

	switch (choice) {
	case WCWIDTH_IMPL_OLD:
		wcwidth_impl_func = &mk_wcwidth;
		break;

	case WCWIDTH_IMPL_SYSTEM:
		wcwidth_impl_func = &system_wcwidth;
		break;

#ifdef HAVE_LIBUTF8PROC
	case WCWIDTH_IMPL_JULIA:
		wcwidth_impl_func = &julia_wcwidth;
		break;
#endif
	}

}

void wcwidth_wrapper_init(void)
{
	int wcwidth_impl_default = 0;
	/* Test against characters that have wcwidth=2
	 * since unicode 5.2 and 9.0 respectively */

	if (system_wcwidth(UNICODE_SQUARE_HIRAGANA_HOKA) == 2 ||
	    system_wcwidth(UNICODE_IRSSI_LOGO) == 2) {
		wcwidth_impl_default = WCWIDTH_IMPL_SYSTEM;
	} else {
		/* Fall back to our own (which implements 5.0) */
		wcwidth_impl_default = WCWIDTH_IMPL_OLD;
	}

#ifdef HAVE_LIBUTF8PROC
	settings_add_choice("misc", "wcwidth_implementation", wcwidth_impl_default, "old;system;julia");
#else
	settings_add_choice("misc", "wcwidth_implementation", wcwidth_impl_default, "old;system");
#endif

	read_settings();
	signal_add_first("setup changed", (SIGNAL_FUNC) read_settings);
}

void wcwidth_wrapper_deinit(void)
{
	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
}
