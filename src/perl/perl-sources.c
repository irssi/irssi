/*
 perl-sources.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#define NEED_PERL_H
#include "module.h"
#include "signals.h"

#include "perl-core.h"
#include "perl-common.h"
#include "perl-sources.h"
#include "misc.h"

typedef struct {
        PERL_SCRIPT_REC *script;
	int tag;
	int refcount;
	int once; /* run only once */

	SV *func;
	SV *data;
} PERL_SOURCE_REC;

static GSList *perl_sources;

static void perl_source_ref(PERL_SOURCE_REC *rec)
{
        rec->refcount++;
}

static int perl_source_unref(PERL_SOURCE_REC *rec)
{
	if (--rec->refcount != 0)
		return TRUE;

        SvREFCNT_dec(rec->data);
        SvREFCNT_dec(rec->func);
	g_free(rec);
	return FALSE;
}

static void perl_source_destroy(PERL_SOURCE_REC *rec)
{
	perl_sources = g_slist_remove(perl_sources, rec);

	g_source_remove(rec->tag);
	rec->tag = -1;

	perl_source_unref(rec);
}

static int perl_source_event(PERL_SOURCE_REC *rec)
{
	dSP;
	int retcount;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_mortalcopy(rec->data));
	PUTBACK;

        perl_source_ref(rec);
	retcount = perl_call_sv(rec->func, G_EVAL|G_SCALAR);
	SPAGAIN;

	if (SvTRUE(ERRSV)) {
                char *error = g_strdup(SvPV(ERRSV, PL_na));
		signal_emit("script error", 2, rec->script, error);
                g_free(error);
	}

	if (perl_source_unref(rec) && rec->once)
		perl_source_destroy(rec);

	PUTBACK;
	FREETMPS;
	LEAVE;

	return 1;
}

int perl_timeout_add(int msecs, SV *func, SV *data, int once)
{
        PERL_SCRIPT_REC *script;
	PERL_SOURCE_REC *rec;
	const char *pkg;

        pkg = perl_get_package();
	script = perl_script_find_package(pkg);
        g_return_val_if_fail(script != NULL, -1);

	rec = g_new0(PERL_SOURCE_REC, 1);
	perl_source_ref(rec);

	rec->once = once;
	rec->script = script;
	rec->func = perl_func_sv_inc(func, pkg);
	rec->data = SvREFCNT_inc(data);
	rec->tag = g_timeout_add(msecs, (GSourceFunc) perl_source_event, rec);

	perl_sources = g_slist_append(perl_sources, rec);
	return rec->tag;
}

int perl_input_add(int source, int condition, SV *func, SV *data, int once)
{
        PERL_SCRIPT_REC *script;
	PERL_SOURCE_REC *rec;
        const char *pkg;

        pkg = perl_get_package();
	script = perl_script_find_package(pkg);
        g_return_val_if_fail(script != NULL, -1);

	rec = g_new0(PERL_SOURCE_REC, 1);
	perl_source_ref(rec);

	rec->once = once;
        rec->script =script;
	rec->func = perl_func_sv_inc(func, pkg);
	rec->data = SvREFCNT_inc(data);

	rec->tag = g_input_add_poll(source, G_PRIORITY_DEFAULT, condition,
			       (GInputFunction) perl_source_event, rec);

	perl_sources = g_slist_append(perl_sources, rec);
	return rec->tag;
}

void perl_source_remove(int tag)
{
	GSList *tmp;

	for (tmp = perl_sources; tmp != NULL; tmp = tmp->next) {
		PERL_SOURCE_REC *rec = tmp->data;

		if (rec->tag == tag) {
			perl_source_destroy(rec);
			break;
		}
	}
}

void perl_source_remove_script(PERL_SCRIPT_REC *script)
{
	GSList *tmp, *next;

	for (tmp = perl_sources; tmp != NULL; tmp = next) {
		PERL_SOURCE_REC *rec = tmp->data;

		next = tmp->next;
                if (rec->script == script)
			perl_source_destroy(rec);
	}
}

void perl_sources_start(void)
{
	perl_sources = NULL;
}

void perl_sources_stop(void)
{
	/* timeouts and input waits */
	while (perl_sources != NULL)
		perl_source_destroy(perl_sources->data);
}
