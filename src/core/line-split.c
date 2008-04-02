/*
 line-split.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

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

#include "module.h"
#include "misc.h"

/* Maximum line length - split to two lines if it's longer than this.

   This is mostly to prevent excessive memory usage. Like if someone DCC
   chats you, you both have very fast connections and the other side sends
   you 100 megs of text without any line feeds -> irssi will (try to)
   allocate 128M of memory for the line and will eventually crash when it
   can't allocate any more memory. If the line is split at every 64k the
   text buffer will free the old lines and the memory usage never gets
   too high. */
#define MAX_CHARS_IN_LINE 65536

struct _LINEBUF_REC {
        int len;
	int alloc;
	int remove;
        char *str;
};

static void linebuf_append(LINEBUF_REC *rec, const char *data, int len)
{
	if (rec->len+len > rec->alloc) {
		rec->alloc = nearest_power(rec->len+len);;
		rec->str = g_realloc(rec->str, rec->alloc);
	}

	memcpy(rec->str + rec->len, data, len);
	rec->len += len;
}

static char *linebuf_find(LINEBUF_REC *rec, char chr)
{
	return memchr(rec->str, chr, rec->len);
}

static int remove_newline(LINEBUF_REC *rec)
{
	char *ptr;

	ptr = linebuf_find(rec, '\n');
	if (ptr == NULL) {
		/* LF wasn't found, wait for more data.. */
		if (rec->len < MAX_CHARS_IN_LINE)
			return 0;

		/* line buffer is too big - force a newline. */
                linebuf_append(rec, "\n", 1);
		ptr = rec->str+rec->len-1;
	}

	rec->remove = (int) (ptr-rec->str)+1;
	if (ptr != rec->str && ptr[-1] == '\r') {
		/* remove CR too. */
		ptr--;
	}

	*ptr = '\0';
	return 1;
}

/* line-split `data'. Initially `*buffer' should contain NULL. */
int line_split(const char *data, int len, char **output, LINEBUF_REC **buffer)
{
	LINEBUF_REC *rec;
	int ret;

	g_return_val_if_fail(data != NULL, -1);
	g_return_val_if_fail(output != NULL, -1);
	g_return_val_if_fail(buffer != NULL, -1);

	if (*buffer == NULL)
		*buffer = g_new0(LINEBUF_REC, 1);
	rec = *buffer;

	if (rec->remove > 0) {
		rec->len -= rec->remove;
		g_memmove(rec->str, rec->str+rec->remove, rec->len);
		rec->remove = 0;
	}

	if (len > 0)
		linebuf_append(rec, data, len);
	else if (len < 0) {
		/* connection closed.. */
		if (rec->len == 0)
			return -1;

		/* no new data got but still something in buffer.. */
		if (linebuf_find(rec, '\n') == NULL) {
			/* connection closed and last line is missing \n ..
			   just add it so we can see if it had
			   anything useful.. */
			linebuf_append(rec, "\n", 1);
		}
	}

	ret = remove_newline(rec);
	*output = rec->str;
	return ret;
}

void line_split_free(LINEBUF_REC *buffer)
{
	if (buffer != NULL) {
		if (buffer->str != NULL) g_free(buffer->str);
		g_free(buffer);
	}
}

/* Return 1 if there is no data in the buffer */
int line_split_is_empty(LINEBUF_REC *buffer)
{
	return buffer->len == 0;
}
