#include "module.h"

static int magic_free_text_dest(pTHX_ SV *sv, MAGIC *mg)
{
	TEXT_DEST_REC *dest = (TEXT_DEST_REC *) mg->mg_ptr;
	char *target = (char *) dest->target;
	g_free(target);
	g_free(dest);
	mg->mg_ptr = NULL;
	sv_setiv(sv, 0);
	return 0;
}

static MGVTBL vtbl_free_text_dest =
{
    NULL, NULL, NULL, NULL, magic_free_text_dest
};

static SV *perl_format_create_dest(SERVER_REC *server, char *target,
				   int level, WINDOW_REC *window)
{
	TEXT_DEST_REC *dest;
	SV *sv, *ret_sv;

	dest = g_new0(TEXT_DEST_REC, 1);
	format_create_dest(dest, server, g_strdup(target), level, window);

	ret_sv = plain_bless(dest, "Irssi::UI::TextDest");

	sv = *hv_fetch(hvref(ret_sv), "_irssi", 6, 0);
	sv_magic(sv, NULL, '~', NULL, 0);

	SvMAGIC(sv)->mg_private = 0x1551; /* HF */
	SvMAGIC(sv)->mg_virtual = &vtbl_free_text_dest;
	SvMAGIC(sv)->mg_ptr = (char *) dest;

	return ret_sv;
}

MODULE = Irssi::UI::Formats  PACKAGE = Irssi
PROTOTYPES: ENABLE

int
format_get_length(str)
	char *str

int
format_real_length(str, len)
	char *str
	int len

void
strip_codes(input)
	char *input
PREINIT:
	char *ret;
PPCODE:
	ret = strip_codes(input);
	XPUSHs(sv_2mortal(new_pv(ret)));
	g_free(ret);


void
format_create_dest(target, level=MSGLEVEL_CLIENTNOTICE, window=NULL)
	char *target
	int level
	Irssi::UI::Window window
PPCODE:
	XPUSHs(sv_2mortal(perl_format_create_dest(NULL, target, level, window)));

#*******************************
MODULE = Irssi::UI::Formats  PACKAGE = Irssi::UI::Window
#*******************************

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

#*******************************
MODULE = Irssi::UI::Formats  PACKAGE = Irssi::Window
#*******************************

void
format_create_dest(window=NULL, level=MSGLEVEL_CLIENTNOTICE)
	Irssi::UI::Window window
	int level
PPCODE:
	XPUSHs(sv_2mortal(perl_format_create_dest(NULL, NULL, level, window)));

#*******************************
MODULE = Irssi::UI::Formats  PACKAGE = Irssi::Server
#*******************************

void
format_create_dest(server, target=NULL, level=MSGLEVEL_CLIENTNOTICE, window=NULL)
	Irssi::Server server
	char *target
	int level
	Irssi::UI::Window window
PPCODE:
	XPUSHs(sv_2mortal(perl_format_create_dest(server, target, level, window)));

#*******************************
MODULE = Irssi::UI::Formats  PACKAGE = Irssi::UI::TextDest
#*******************************

void
print(dest, str)
	Irssi::UI::TextDest dest
	char *str
CODE:
	printtext_dest(dest, "%s", str);
