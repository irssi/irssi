#include "module.h"

MODULE = Irssi::TextUI::TextBuffer  PACKAGE = Irssi
PROTOTYPES: ENABLE

Irssi::TextUI::TextBuffer
textbuffer_create()

#*******************************
MODULE = Irssi::TextUI::TextBuffer  PACKAGE = Irssi::TextUI::TextBuffer  PREFIX = textbuffer_
#*******************************

void
textbuffer_destroy(buffer)
	Irssi::TextUI::TextBuffer buffer

Irssi::TextUI::Line
textbuffer_append(buffer, data, len, info)
	Irssi::TextUI::TextBuffer buffer
	char *data
	int len
	Irssi::TextUI::LineInfo info

Irssi::TextUI::Line
textbuffer_insert(buffer, insert_after, data, len, info)
	Irssi::TextUI::TextBuffer buffer
	Irssi::TextUI::Line insert_after
	char *data
	int len
	Irssi::TextUI::LineInfo info

void
textbuffer_remove(buffer, line)
	Irssi::TextUI::TextBuffer buffer
	Irssi::TextUI::Line line

void
textbuffer_remove_all_lines(buffer)
	Irssi::TextUI::TextBuffer buffer

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
textbuffer_line_ref(line)
	Irssi::TextUI::Line line

void
textbuffer_line_unref(line, buffer)
	Irssi::TextUI::Line line
	Irssi::TextUI::TextBuffer buffer
CODE:
	textbuffer_line_unref(buffer, line);

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

