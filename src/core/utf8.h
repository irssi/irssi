#ifndef IRSSI_CORE_UTF8_H
#define IRSSI_CORE_UTF8_H

/* XXX I didn't check the encoding range of big5+. This is standard big5. */
#define is_big5_los(lo) (0x40 <= (lo) && (lo) <= 0x7E) /* standard */
#define is_big5_lox(lo) (0x80 <= (lo) && (lo) <= 0xFE) /* extended */
#define is_big5_lo(lo)	((is_big5_los(lo) || is_big5_lox(lo)))
#define is_big5_hi(hi)  (0x81 <= (hi) && (hi) <= 0xFE)
#define is_big5(hi,lo) (is_big5_hi(hi) && is_big5_lo(lo))

#include <glib.h>
typedef guint32 unichar;

/* Returns width for character (0-2). */
int i_wcwidth(unichar c);

/* Older variant of the above */
int mk_wcwidth(unichar c);

/* Signature for wcwidth implementations */
typedef int (*WCWIDTH_FUNC) (unichar ucs);

/* Advance the str pointer one character further; return the number of columns
 * occupied by the skipped character.
 */
int string_advance(char const **str, int policy);

/* TREAT_STRING_AS_BYTES means strings are to be treated using strncpy,
 * strnlen, etc.
 * TREAT_STRING_AS_UTF8 means strings are to be treated using g_utf8_*
 * functions.
 */
enum str_policy {
	TREAT_STRING_AS_BYTES,
	TREAT_STRING_AS_UTF8
};

/* Return how the str string ought to be treated: TREAT_STRING_AS_UTF8 if the
 * terminal handles UTF-8 and if the string appears to be a valid UTF-8 string;
 * TREAT_STRING_AS_BYTES otherwise.
 */
int string_policy(const char *str);

/* Return the length of the str string according to the given policy; if policy
 * is -1, this function will call string_policy().
 */
int string_length(const char *str, int policy);
/* Return the screen width of the str string according to the given policy; if
 * policy is -1, this function will call string_policy().
 */
int string_width(const char *str, int policy);

/* Return the amount of characters from str it takes to reach n columns, or -1 if
 * str is NULL. Optionally return the equivalent amount of bytes.
 * If policy is -1, this function will call string_policy().
 */
int string_chars_for_width(const char *str, int policy, unsigned int n, unsigned int *bytes);

/* Calculate display width of a single unichar, considering it might be part of
 * a grapheme cluster. For best results, use string_advance() on UTF-8 strings. */
int unichar_width(unichar chr);

/* Advance through unichar array by one grapheme cluster, return display width.
 * Updates *pos to point after the cluster. Use for GUI code with unichar arrays. */
int unichar_array_advance_cluster(const unichar *text, int text_len, int *pos);

/* Move backward through unichar array by one grapheme cluster, return display width.
 * Updates *pos to point to the start of the previous cluster. */
int unichar_array_move_cluster_backward(const unichar *text, int text_len, int *pos);

/* Find the start of the grapheme cluster containing the given codepoint position.
 * Returns the codepoint index of the cluster start. */
int unichar_array_find_cluster_start(const unichar *text, int text_len, int pos);

/* Initialize UTF-8 debugging system */
void utf8_init(void);

/* Deinitialize UTF-8 debugging system */
void utf8_deinit(void);

#define unichar_isprint(c) (((c) & ~0x80) >= 32)
#define is_utf8_leading(c) (((c) & 0xc0) != 0x80)

#endif
