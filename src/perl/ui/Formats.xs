#include "module.h"

MODULE = Irssi::UI::Formats  PACKAGE = Irssi::UI::Window
PROTOTYPES: ENABLE

void
format_get_text(window, module, server, target, formatnum, ...)
	Irssi::UI::Window window
	char *module
	Irssi::Server server
	char *target
	int formatnum
PREINIT:
	char **charargs;
	char *ret;
	int n;
PPCODE:
	charargs = g_new0(char *, items-5+1);
	charargs[items-5] = NULL;
        for (n = 5; n < items; n++) {
		charargs[n-5] = (char *)SvPV(ST(n), PL_na);
	}
	ret = format_get_text(module, window, server, target, formatnum, charargs);
	g_free(charargs);

	XPUSHs(sv_2mortal(new_pv(ret)));
	g_free_not_null(ret);
