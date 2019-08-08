#ifndef IRSSI_PERL_TEXTUI_WRAPPER_BUFFER_LINE_H
#define IRSSI_PERL_TEXTUI_WRAPPER_BUFFER_LINE_H

/* This Buffer_Line_Wrapper is a compatibility shim so that the Perl
 * API does not change in Irssi ABI 24 even though the C API was
 * changed. That way scripts can continue to work unchanged. */

struct Buffer_Line_Wrapper {
	LINE_REC *line;
	TEXT_BUFFER_REC *buffer;
};

#define Line(wrapper) ((wrapper) == NULL ? NULL : (wrapper)->line)

static int magic_free_buffer_line(pTHX_ SV *sv, MAGIC *mg)
{
	struct Buffer_Line_Wrapper *wrap = (struct Buffer_Line_Wrapper *) mg->mg_ptr;
	g_free(wrap);
	mg->mg_ptr = NULL;
	sv_setiv(sv, 0);
	return 0;
}

static MGVTBL vtbl_free_buffer_line = { NULL, NULL, NULL, NULL, magic_free_buffer_line };

static struct Buffer_Line_Wrapper *perl_wrap_buffer_line(TEXT_BUFFER_REC *buffer, LINE_REC *line)
{
	struct Buffer_Line_Wrapper *wrap;

	if (line == NULL)
		return NULL;

	wrap = g_new0(struct Buffer_Line_Wrapper, 1);
	wrap->buffer = buffer;
	wrap->line = line;

	return wrap;
}

/* This function is more or less a copy of plain_bless, but with a
   special divertion to put the wrapper in _wrapper and the original
   line pointer in _irssi, in order to stay compatible with signals
   and scripts */
static SV *perl_buffer_line_bless(struct Buffer_Line_Wrapper *object)
{
	SV *ret, **tmp;
	HV *hv;
	const char *stash = "Irssi::TextUI::Line";

	if (object == NULL)
		return &PL_sv_undef;

	ret = irssi_bless_plain(stash, object);
	hv = hvref(ret);

	tmp = hv_fetch(hv, "_irssi", 6, 0);

	sv_magic(*tmp, NULL, '~', NULL, 0);

	SvMAGIC(*tmp)->mg_private = 0x1551; /* HF */
	SvMAGIC(*tmp)->mg_virtual = &vtbl_free_buffer_line;
	SvMAGIC(*tmp)->mg_ptr = (char *) object;

	(void) hv_store(hv, "_wrapper", 8, *tmp, 0);
	/* We have to put the Line Pointer in _irssi, not the
	   compatibility wrapper */
	*tmp = newSViv((IV) object->line);
	return ret;
}

/* This function is a copy of irssi_ref_object, but looking up the
   wrapper object in _wrapper instead */
static void *irssi_ref_buffer_line_wrap(SV *o)
{
	SV **sv;
	HV *hv;
	void *p;

	hv = hvref(o);
	if (hv == NULL)
		return NULL;

	sv = hv_fetch(hv, "_wrapper", 8, 0);
	if (sv == NULL)
		croak("variable is damaged");
	p = GINT_TO_POINTER(SvIV(*sv));
	return p;
}

#endif
