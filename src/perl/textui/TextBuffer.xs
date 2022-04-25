#define PERL_NO_GET_CONTEXT
#include "module.h"
#include "wrapper_buffer_line.h"
#include <irssi/src/fe-text/textbuffer-formats.h>

MODULE = Irssi::TextUI::TextBuffer  PACKAGE = Irssi
PROTOTYPES: ENABLE

#*******************************
MODULE = Irssi::TextUI::TextBuffer  PACKAGE = Irssi
#*******************************

int
COLORING_STRIP()
CODE:
	RETVAL = COLORING_STRIP;
OUTPUT:
	RETVAL

int
COLORING_EXPAND()
CODE:
	RETVAL = COLORING_EXPAND;
OUTPUT:
	RETVAL

int
COLORING_UNEXPAND()
CODE:
	RETVAL = COLORING_UNEXPAND;
OUTPUT:
	RETVAL

int
COLORING_RAW()
CODE:
	RETVAL = COLORING_RAW;
OUTPUT:
	RETVAL

#*******************************
MODULE = Irssi::TextUI::TextBuffer  PACKAGE = Irssi::TextUI::Line  PREFIX = textbuffer_line_
#*******************************

Irssi::TextUI::Line
textbuffer_line_prev(line)
	Irssi::TextUI::Line line
CODE:
	RETVAL = perl_wrap_buffer_line(line->buffer, line->line->prev);
OUTPUT:
	RETVAL

Irssi::TextUI::Line
textbuffer_line_next(line)
	Irssi::TextUI::Line line
CODE:
	RETVAL = perl_wrap_buffer_line(line->buffer, line->line->next);
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
	textbuffer_line2text(line->buffer, line->line, coloring, str);
	result = new_pv(str->str);
	XPUSHs(sv_2mortal(result));
	g_string_free(str, TRUE);

void
textbuffer_line_get_format(line)
	Irssi::TextUI::Line line
PREINIT:
	HV *hv;
	AV *av;
	LINE_REC *l;
	TEXT_BUFFER_FORMAT_REC *f;
	int i;
PPCODE:
	hv = newHV();
	l = line->line;
	if (l->info.format != NULL) {
		f = l->info.format;
		(void) hv_store(hv, "module", 6, new_pv(f->module), 0);
		(void) hv_store(hv, "format", 6, new_pv(f->format), 0);
		(void) hv_store(hv, "server_tag", 10, new_pv(f->server_tag), 0);
		(void) hv_store(hv, "target", 6, new_pv(f->target), 0);
		(void) hv_store(hv, "nick", 4, new_pv(f->nick), 0);
		av = newAV();
		for (i = 0; i < f->nargs; i++) {
			av_push(av, new_pv(f->args[i]));
		}
		(void) hv_store(hv, "args", 4, newRV_noinc((SV *) av), 0);
	} else {
		(void) hv_store(hv, "text", 4, new_pv(l->info.text), 0);
	}
	XPUSHs(sv_2mortal(newRV_noinc((SV *) hv)));

Irssi::UI::LineInfoMeta
textbuffer_line_get_meta(line)
	Irssi::TextUI::Line line
CODE:
	RETVAL = line->line->info.meta;
OUTPUT:
	RETVAL
