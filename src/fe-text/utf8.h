#ifndef __UTF8_H
#define __UTF8_H

/* Returns -2 = invalid, -1 = need more data, otherwise unichar. */
unichar get_utf8_char(const unsigned char **ptr, int len);

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

/* Returns width for character (0-2). */
int utf8_width(unichar c);

#endif
