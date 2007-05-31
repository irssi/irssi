#ifndef __UTF8_H
#define __UTF8_H

/* Returns -2 = invalid, -1 = need more data, otherwise unichar. */
int get_utf8_char(const unsigned char **ptr, int len, unichar *chr_r);

/* Returns length of UTF8 string */
int strlen_utf8(const char *str);

/* UTF-8 -> unichar string. The NUL is copied as well. */
void utf8_to_utf16(const char *str, unichar *out);

/* unichar -> UTF-8 string. outbuf must be at least 6 chars long.
   Returns outbuf string length. */
int utf16_char_to_utf8(unichar c, char *outbuf);

/* unichar -> UTF-8 string. The NUL is copied as well.
   Make sure out is at least 6 x length of str. */
void utf16_to_utf8(const unichar *str, char *out);

/* unichar -> UTF-8 string with position transformed. The NUL is copied as well.
   Make sure out is at least 6 x length of str. */
void utf16_to_utf8_with_pos(const unichar *str, int spos, char *out, int *opos);

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
