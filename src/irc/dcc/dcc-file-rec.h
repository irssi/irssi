#include "dcc-rec.h"

unsigned long size, skipped; /* file size / skipped at start */
int fhandle; /* file handle */
int queue; /* queue number */

/* counter buffer */
char count_buf[4];
int count_pos;

