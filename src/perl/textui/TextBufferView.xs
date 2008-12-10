#include "module.h"

MODULE = Irssi::TextUI::TextBufferView  PACKAGE = Irssi::TextUI::TextBuffer  PREFIX = textbuffer_
PROTOTYPES: ENABLE

#*******************************
MODULE = Irssi::TextUI::TextBufferView  PACKAGE = Irssi::TextUI::TextBufferView  PREFIX = textbuffer_view_
#*******************************

void
textbuffer_view_set_default_indent(view, default_indent, longword_noindent)
	Irssi::TextUI::TextBufferView view
	int default_indent
	int longword_noindent
CODE:
	textbuffer_view_set_default_indent(view, default_indent, longword_noindent, NULL);

void
textbuffer_view_set_scroll(view, scroll)
	Irssi::TextUI::TextBufferView view
	int scroll

void
textbuffer_view_clear(view)
	Irssi::TextUI::TextBufferView view

Irssi::TextUI::Line
textbuffer_view_get_lines(view)
	Irssi::TextUI::TextBufferView view

void
textbuffer_view_scroll(view, lines)
	Irssi::TextUI::TextBufferView view
	int lines

void
textbuffer_view_scroll_line(view, line)
	Irssi::TextUI::TextBufferView view
	Irssi::TextUI::Line line

Irssi::TextUI::LineCache
textbuffer_view_get_line_cache(view, line)
	Irssi::TextUI::TextBufferView view
	Irssi::TextUI::Line line

void
textbuffer_view_remove_line(view, line)
	Irssi::TextUI::TextBufferView view
	Irssi::TextUI::Line line

void
textbuffer_view_remove_all_lines(view)
	Irssi::TextUI::TextBufferView view

void
textbuffer_view_set_bookmark(view, name, line)
	Irssi::TextUI::TextBufferView view
	char *name
	Irssi::TextUI::Line line

void
textbuffer_view_set_bookmark_bottom(view, name)
	Irssi::TextUI::TextBufferView view
	char *name

Irssi::TextUI::Line
textbuffer_view_get_bookmark(view, name)
	Irssi::TextUI::TextBufferView view
	char *name

void
textbuffer_view_redraw(view)
	Irssi::TextUI::TextBufferView view

#*******************************
MODULE = Irssi::TextUI::TextBufferView  PACKAGE = Irssi::UI::Window
#*******************************

Irssi::TextUI::TextBufferView
view(window)
	Irssi::UI::Window window
CODE:
	RETVAL = WINDOW_GUI(window)->view;
OUTPUT:
	RETVAL
