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
	TEXT_DEST_REC dest;
	THEME_REC *theme;
	char **charargs;
	char *ret;
	int n;
PPCODE:
	charargs = g_new0(char *, items-5+1);
        for (n = 5; n < items; n++) {
		charargs[n-5] = (char *)SvPV(ST(n), PL_na);
	}

	format_create_dest(&dest, server, target, 0, window);
	theme = window_get_theme(dest.window);

	ret = format_get_text_theme_charargs(theme, module, &dest, formatnum, charargs);
	g_free(charargs);

	XPUSHs(sv_2mortal(new_pv(ret)));
	g_free_not_null(ret);
