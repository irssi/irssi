#ifndef __UTF8_H
#define __UTF8_H

/* XXX I didn't check the encoding range of big5+. This is standard big5. */
#define is_big5_los(lo) (0x40 <= (lo) && (lo) <= 0x7E) /* standard */
#define is_big5_lox(lo) (0x80 <= (lo) && (lo) <= 0xFE) /* extended */
#define is_big5_lo(lo)	((is_big5_los(lo) || is_big5_lox(lo)))
#define is_big5_hi(hi)  (0x81 <= (hi) && (hi) <= 0xFE)
#define is_big5(hi,lo) (is_big5_hi(hi) && is_big5_lo(lo))

/* Returns width for character (0-2). */
int mk_wcwidth(unichar c);

#define unichar_isprint(c) (((c) & ~0x80) >= 32)

#endif
