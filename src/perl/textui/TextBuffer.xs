#include "module.h"

MODULE = Irssi::TextUI::TextBuffer  PACKAGE = Irssi
PROTOTYPES: ENABLE

#*******************************
MODULE = Irssi::TextUI::TextBuffer  PACKAGE = Irssi::TextUI::Line  PREFIX = textbuffer_line_
#*******************************

Irssi::TextUI::Line
textbuffer_line_prev(line)
	Irssi::TextUI::Line line
CODE:
	RETVAL = line->prev;
OUTPUT:
	RETVAL

Irssi::TextUI::Line
textbuffer_line_next(line)
	Irssi::TextUI::Line line
CODE:
	RETVAL = line->next;
OUTPUT:
	RETVAL

void
textbuffer_line_get_text(line, coloring)
	Irssi::TextUI::Line line
	int coloring
PREINIT:
	GString *str;
	SV *result;
PPCODE:
	str = g_string_new(NULL);
	textbuffer_line2text(line, coloring, str);
	result = new_pv(str->str);
	XPUSHs(sv_2mortal(result));
	g_string_free(str, TRUE);

