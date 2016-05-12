#ifndef __UTF8_H
#define __UTF8_H

/* XXX I didn't check the encoding range of big5+. This is standard big5. */
#define is_big5_los(lo) (0x40 <= (lo) && (lo) <= 0x7E) /* standard */
#define is_big5_lox(lo) (0x80 <= (lo) && (lo) <= 0xFE) /* extended */
#define is_big5_lo(lo)	((is_big5_los(lo) || is_big5_lox(lo)))
#define is_big5_hi(hi)  (0x81 <= (hi) && (hi) <= 0xFE)
#define is_big5(hi,lo) (is_big5_hi(hi) && is_big5_lo(lo))

#include <glib.h>
typedef guint32 unichar;

/* Returns width for character (0-2). */
int mk_wcwidth(unichar c);

/* Advance the str pointer one character further; return the number of columns
 * occupied by the skipped character.
 */
int string_advance(char const **str, gboolean utf8);

#define unichar_isprint(c) (((c) & ~0x80) >= 32)
#define is_utf8_leading(c) (((c) & 0xc0) != 0x80)

#endif
