#include "printtext.h"

enum {
	IRCTXT_MODULE_NAME,

	IRCTXT_FILL_1,

	IRCTXT_AUTOIGNORE,
	IRCTXT_AUTOUNIGNORE
};

extern FORMAT_REC fecommon_irc_flood_formats[];
#define MODULE_FORMATS fecommon_irc_flood_formats
