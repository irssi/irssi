#ifndef __LINE_SPLIT_H
#define __LINE_SPLIT_H

/* line-split `data'. Initially `*buffer' should contain NULL. */
int line_split(const char *data, int len, char **output, LINEBUF_REC **buffer);
void line_split_free(LINEBUF_REC *buffer);

/* Return 1 if there is no data in the buffer */
int line_split_is_empty(LINEBUF_REC *buffer);

#endif
