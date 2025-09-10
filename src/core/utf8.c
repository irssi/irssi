/* utf8.c - Operations on UTF-8 strings.
 *
 * Copyright (C) 2002 Timo Sirainen
 *
 * Based on GLib code by
 *
 * Copyright (C) 1999 Tom Tromey
 * Copyright (C) 2000 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <irssi/src/core/utf8.h>
#include "module.h"

/* Provide is_utf8(): */
#include <irssi/src/core/recode.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/settings.h>

#ifdef HAVE_LIBUTF8PROC
#include <utf8proc.h>

/* Advance the str pointer one grapheme cluster further when utf8proc is available,
 * or fall back to single character advancement. Returns display width. */
static int string_advance_with_grapheme_support(char const **str, int policy)
{
	utf8proc_int32_t codepoint, prev_codepoint = 0;
	utf8proc_int32_t state = 0;
	const char *start = *str;
	const char *pos = *str;
	int cluster_width = 0;
	utf8proc_ssize_t bytes;

	if (policy != TREAT_STRING_AS_UTF8) {
		/* Fall back to byte-based processing */
		*str += 1;
		return 1;
	}

	if (*pos == '\0') {
		return 0;
	}

	/* Process codepoints until we find a grapheme boundary */
	while (*pos != '\0') {
		bytes = utf8proc_iterate((const utf8proc_uint8_t *)pos, -1, &codepoint);
		if (bytes < 0) {
			/* Invalid UTF-8, skip one byte */
			*str = pos + 1;
			return 1;
		}

		/* Check if this is a grapheme boundary */
		if (pos != start && utf8proc_grapheme_break_stateful(prev_codepoint, codepoint, &state)) {
			/* We found the end of the current cluster */
			break;
		}

		/* Add this codepoint's width to the cluster */
		if (unichar_isprint(codepoint)) {
			int char_width = i_wcwidth(codepoint);
			if (char_width > cluster_width) {
				cluster_width = char_width;
			}
		}

		prev_codepoint = codepoint;
		pos += bytes;
	}

	*str = pos;
	return cluster_width > 0 ? cluster_width : 1;
}
#endif

int string_advance(char const **str, int policy)
{
#ifdef HAVE_LIBUTF8PROC
	return string_advance_with_grapheme_support(str, policy);
#else
	if (policy == TREAT_STRING_AS_UTF8) {
		gunichar c;

		c = g_utf8_get_char(*str);
		*str = g_utf8_next_char(*str);

		return unichar_isprint(c) ? i_wcwidth(c) : 1;
	} else {
		/* Assume TREAT_STRING_AS_BYTES: */
		*str += 1;

		return 1;
	}
#endif
}

int string_policy(const char *str)
{
	if (is_utf8()) {
		if (str == NULL || g_utf8_validate(str, -1, NULL)) {
			/* No string provided or valid UTF-8 string: treat as UTF-8: */
			return TREAT_STRING_AS_UTF8;
		}
	}
	return TREAT_STRING_AS_BYTES;
}

int string_length(const char *str, int policy)
{
	g_return_val_if_fail(str != NULL, 0);

	if (policy == -1) {
		policy = string_policy(str);
	}

	if (policy == TREAT_STRING_AS_UTF8) {
		return g_utf8_strlen(str, -1);
	}
	else {
		/* Assume TREAT_STRING_AS_BYTES: */
		return strlen(str);
	}
}

int string_width(const char *str, int policy)
{
	int len;

	g_return_val_if_fail(str != NULL, 0);

	if (policy == -1) {
		policy = string_policy(str);
	}

	len = 0;
	while (*str != '\0') {
		len += string_advance(&str, policy);
	}
	return len;
}

int string_chars_for_width(const char *str, int policy, unsigned int n, unsigned int *bytes)
{
	const char *c, *previous_c;
	int str_width, char_width, char_count;

	g_return_val_if_fail(str != NULL, -1);

	/* Handle the dummy case where n is 0: */
	if (n == 0) {
		if (bytes != NULL) {
			*bytes = 0;
		}
		return 0;
	}

	if (policy == -1) {
		policy = string_policy(str);
	}

	/* Iterate over characters until we reach n: */
	char_count = 0;
	str_width = 0;
	c = str;
	while (*c != '\0') {
		previous_c = c;
		char_width = string_advance(&c, policy);
		if (str_width + char_width > n) {
			/* We stepped beyond n, get one step back and stop there: */
			c = previous_c;
			break;
		}
		++ char_count;
		str_width += char_width;
	}
	/* At this point, we know that char_count characters reach str_width
	 * columns, which is less than or equal to n. */

	/* Optionally provide the equivalent amount of bytes: */
	if (bytes != NULL) {
		*bytes = c - str;
	}
	return char_count;
}

int unichar_width(unichar chr)
{
	int width;

	/* For individual codepoints, fall back to standard wcwidth.
	 * This is not grapheme-cluster aware, but better than nothing
	 * for GUI code that works with unichar arrays instead of UTF-8 strings.
	 *
	 * Note: For proper emoji support, use string_advance() on UTF-8 strings
	 * instead of processing individual codepoints.
	 */
	if (!unichar_isprint(chr))
		return 1;

	width = i_wcwidth(chr);
	return width < 0 ? 1 : width;
}

int unichar_array_advance_cluster(const unichar *text, int text_len, int *pos)
{
#ifdef HAVE_LIBUTF8PROC
	utf8proc_int32_t state = 0;
	int cluster_width = 0;
	utf8proc_int32_t first_codepoint, codepoint;
	int char_width;
	int has_variation_selector = 0;

	if (*pos >= text_len) {
		return 0;
	}

	/* Process first codepoint */
	first_codepoint = text[*pos];

	if (unichar_isprint(first_codepoint)) {
		char_width = i_wcwidth(first_codepoint);
		if (char_width > cluster_width) {
			cluster_width = char_width;
		}
	}

	(*pos)++;

	/* Process additional codepoints until we find a grapheme boundary */
	while (*pos < text_len) {
		codepoint = text[*pos];

		/* Check if this is a grapheme boundary */
		if (utf8proc_grapheme_break_stateful(text[*pos - 1], codepoint, &state)) {
			/* We found the end of the current cluster */
			break;
		}

		/* Check for variation selector */
		if (codepoint == 0xFE0F) {
			has_variation_selector = 1;
		}

		/* Add this codepoint's width to the cluster (usually 0 for combining chars) */
		if (unichar_isprint(codepoint)) {
			char_width = i_wcwidth(codepoint);
			if (char_width > cluster_width) {
				cluster_width = char_width;
			}
		}

		(*pos)++;
	}

	/* Special handling for emoji with variation selector */
	if (has_variation_selector && cluster_width == 1) {
		/* Base emoji (like ❣ U+2763, ♥ U+2665) + variation selector should have width 2 */
		cluster_width = 2;
	}

	return cluster_width > 0 ? cluster_width : 1;
#else
	/* Fall back to single character processing when utf8proc unavailable */
	unichar chr;
	int width;

	if (*pos >= text_len) {
		return 0;
	}

	chr = text[*pos];
	(*pos)++;

	/* Bounds check after increment */
	if (*pos > text_len) {
		*pos = text_len;
	}

	if (!unichar_isprint(chr))
		return 1;

	width = i_wcwidth(chr);
	return width < 0 ? 1 : width;
#endif
}

int unichar_array_move_cluster_backward(const unichar *text, int text_len, int *pos)
{
#ifdef HAVE_LIBUTF8PROC
	utf8proc_int32_t state = 0;
	int cluster_start;
	int cluster_width = 0;
	int temp_pos;

	if (*pos <= 0) {
		return 0;
	}

	/* Move back one codepoint first */
	(*pos)--;

	/* Find the beginning of the current grapheme cluster by going backwards */
	cluster_start = *pos;

	/* Go back to find cluster boundary */
	while (cluster_start > 0) {
		/* Check if there's a grapheme boundary between previous char and current */
		if (utf8proc_grapheme_break_stateful(text[cluster_start - 1], text[cluster_start], &state)) {
			/* Found boundary, cluster starts here */
			break;
		}
		cluster_start--;
	}

	/* Calculate width of this cluster */
	temp_pos = cluster_start;
	while (temp_pos < text_len && temp_pos < *pos + 1) {
		unichar codepoint = text[temp_pos];
		if (unichar_isprint(codepoint)) {
			int char_width = i_wcwidth(codepoint);
			if (char_width > cluster_width) {
				cluster_width = char_width;
			}
		}
		temp_pos++;
	}

	*pos = cluster_start;
	return cluster_width > 0 ? cluster_width : 1;
#else
	/* Fall back to single character processing when utf8proc unavailable */
	unichar chr;
	int width;

	if (*pos <= 0) {
		return 0;
	}

	(*pos)--;
	chr = text[*pos];

	if (!unichar_isprint(chr))
		return 1;

	width = i_wcwidth(chr);
	return width < 0 ? 1 : width;
#endif
}

int unichar_array_find_cluster_start(const unichar *text, int text_len, int pos)
{
#ifdef HAVE_LIBUTF8PROC
	utf8proc_int32_t state = 0;
	int cluster_start = pos;

	if (pos <= 0 || pos >= text_len) {
		return pos;
	}

	/* Go back to find cluster boundary */
	while (cluster_start > 0) {
		/* Check if there's a grapheme boundary between previous char and current */
		if (utf8proc_grapheme_break_stateful(text[cluster_start - 1], text[cluster_start], &state)) {
			/* Found boundary, cluster starts here */
			break;
		}
		cluster_start--;
	}

	return cluster_start;
#else
	/* Fall back to single character processing when utf8proc unavailable */
	return pos;
#endif
}

void utf8_init(void)
{
	/* no-op */
}

void utf8_deinit(void)
{
	/* Nothing to clean up currently */
}
