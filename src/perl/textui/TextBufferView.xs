#include "module.h"

static char *default_indent_func;

static int perl_indent_func(TEXT_BUFFER_VIEW_REC *view,
			    LINE_REC *line, int ypos)
{
	dSP;
	int retcount, ret;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(plain_bless(view, "Irssi::TextUI::TextBufferView")));
	XPUSHs(sv_2mortal(plain_bless(line, "Irssi::TextUI::Line")));
	XPUSHs(sv_2mortal(newSViv(ypos)));
	PUTBACK;

	retcount = perl_call_pv(default_indent_func, G_EVAL|G_DISCARD);
	SPAGAIN;

        ret = 0;
	if (SvTRUE(ERRSV)) {
		STRLEN n_a;
                char *package;

                package = perl_function_get_package(default_indent_func);
		signal_emit("script error", 2,
			    perl_script_find_package(package),
			    SvPV(ERRSV, n_a));
                g_free(package);
	} else if (retcount > 0) {
		ret = POPi;
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

        return ret;
}

void perl_textbuffer_view_init(void)
{
        default_indent_func = NULL;
}

void perl_textbuffer_view_deinit(void)
{
        g_free_not_null(default_indent_func);
}

MODULE = Irssi::TextUI::TextBufferView  PACKAGE = Irssi::TextUI::TextBuffer  PREFIX = textbuffer_
PROTOTYPES: ENABLE

Irssi::TextUI::TextBufferView
textbuffer_view_create(buffer, width, height, scroll)
	Irssi::TextUI::TextBuffer buffer
	int width
	int height
	int scroll

void
gui_windows_set_default_indent_func(func)
        char *func
CODE:
        g_free_not_null(default_indent_func);
        default_indent_func = g_strdup(func);
        gui_windows_set_default_indent_func(perl_indent_func);

#*******************************
MODULE = Irssi::TextUI::TextBufferView  PACKAGE = Irssi::TextUI::TextBufferView  PREFIX = textbuffer_view_
#*******************************

void
textbuffer_view_destroy(view)
	Irssi::TextUI::TextBufferView view

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
textbuffer_view_resize(view, width, height)
	Irssi::TextUI::TextBufferView view
	int width
	int height

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
textbuffer_view_insert_line(view, line)
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
