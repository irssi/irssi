#include "printtext.h"

enum {
	IRCTXT_MODULE_NAME,

	IRCTXT_LASTLOG_START,
	IRCTXT_LASTLOG_END,

        IRCTXT_WINDOW_TOO_SMALL,
        IRCTXT_CANT_HIDE_LAST
};

extern FORMAT_REC gui_text_formats[];
#define MODULE_FORMATS gui_text_formats

#include "printformat.h"
