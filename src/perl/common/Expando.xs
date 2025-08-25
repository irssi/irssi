#define PERL_NO_GET_CONTEXT
#include "module.h"
#include <irssi/src/core/expandos.h>

typedef struct {
	PERL_SCRIPT_REC *script;
	SV *func;
} PerlExpando;

static GHashTable *perl_expando_defs;

static char *sig_perl_expando(SERVER_REC *server, void *item, int *free_ret);

static int check_expando_destroy(char *key, PerlExpando *rec,
				 PERL_SCRIPT_REC *script)
{
	if (rec->script == script) {
                expando_destroy(key, sig_perl_expando);
		SvREFCNT_dec(rec->func);
		g_free(key);
		g_free(rec);
		return TRUE;
	}

        return FALSE;
}

static void script_unregister_expandos(PERL_SCRIPT_REC *script)
{
	g_hash_table_foreach_remove(perl_expando_defs,
				    (GHRFunc) check_expando_destroy, script);
}

void perl_expando_init(void)
{
	perl_expando_defs = g_hash_table_new((GHashFunc) g_str_hash,
					     (GCompareFunc) g_str_equal);
	signal_add("script destroyed", (SIGNAL_FUNC) script_unregister_expandos);
}

static void expando_def_destroy(char *key, PerlExpando *rec)
{
	SvREFCNT_dec(rec->func);
	g_free(key);
	g_free(rec);
}

void perl_expando_deinit(void)
{
	signal_remove("script destroyed", (SIGNAL_FUNC) script_unregister_expandos);

	g_hash_table_foreach(perl_expando_defs,
			     (GHFunc) expando_def_destroy, NULL);
	g_hash_table_destroy(perl_expando_defs);
}

static char *perl_expando_event(PerlExpando *rec, SERVER_REC *server,
				WI_ITEM_REC *item, int *free_ret)
{
	dSP;
	char *ret;
	int retcount;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(sv_2mortal(iobject_bless(server)));
	XPUSHs(sv_2mortal(iobject_bless(item)));
	PUTBACK;

	retcount = perl_call_sv(rec->func, G_EVAL|G_SCALAR);
	SPAGAIN;

	ret = NULL;
	if (SvTRUE(ERRSV)) {
		char *error;
		PERL_SCRIPT_REC *script = rec->script;

		(void) POPs;
		/* call putback before emitting script error signal as that
		 * could manipulate the perl stack. */
		PUTBACK;
		/* make sure we don't get back here */
		if (script != NULL)
			script_unregister_expandos(script);
		/* rec has been freed now */

		error = g_strdup(SvPV_nolen(ERRSV));
		signal_emit("script error", 2, script, error);
		g_free(error);
	} else if (retcount > 0) {
		ret = g_strdup(POPp);
		*free_ret = TRUE;
		PUTBACK;
	}

	FREETMPS;
	LEAVE;

	return ret;
}

static char *sig_perl_expando(SERVER_REC *server, void *item, int *free_ret)
{
        PerlExpando *rec;

	rec = g_hash_table_lookup(perl_expando_defs, current_expando);
	if (rec != NULL)
		return perl_expando_event(rec, server, item, free_ret);
	return NULL;
}

static void expando_signals_add_hash(const char *key, SV *signals)
{
	HV *hv;
        HE *he;
	I32 len;
	const char *argstr;
	ExpandoArg arg;

	if (!is_hvref(signals)) {
		croak("Usage: Irssi::expando_create(key, func, hash)");
		return;
	}

        hv = hvref(signals);
	hv_iterinit(hv);
	while ((he = hv_iternext(hv)) != NULL) {
		SV *argsv = HeVAL(he);
		argstr = SvPV_nolen(argsv);

		if (g_ascii_strcasecmp(argstr, "none") == 0)
			arg = EXPANDO_ARG_NONE;
		else if (g_ascii_strcasecmp(argstr, "server") == 0)
			arg = EXPANDO_ARG_SERVER;
		else if (g_ascii_strcasecmp(argstr, "window") == 0)
			arg = EXPANDO_ARG_WINDOW;
		else if (g_ascii_strcasecmp(argstr, "windowitem") == 0)
			arg = EXPANDO_ARG_WINDOW_ITEM;
		else if (g_ascii_strcasecmp(argstr, "never") == 0)
			arg = EXPANDO_NEVER;
		else {
			croak("Unknown signal type: %s", argstr);
			break;
		}
		expando_add_signal(key, hv_iterkey(he, &len), arg);
	}
}

MODULE = Irssi::Expando  PACKAGE = Irssi
PROTOTYPES: ENABLE

void
expando_create(key, func, signals)
	char *key
	SV *func
	SV *signals
PREINIT:
        PerlExpando *rec;
CODE:
	rec = g_new0(PerlExpando, 1);
	rec->script = perl_script_find_package(perl_get_package());
        rec->func = perl_func_sv_inc(func, perl_get_package());

	expando_create(key, sig_perl_expando, NULL);
	g_hash_table_insert(perl_expando_defs, g_strdup(key), rec);
        expando_signals_add_hash(key, signals);

void
expando_destroy(name)
	char *name
PREINIT:
        gpointer key, value;
CODE:
	if (g_hash_table_lookup_extended(perl_expando_defs, name, &key, &value)) {
                g_hash_table_remove(perl_expando_defs, name);
		g_free(key);
		SvREFCNT_dec((SV *) value);
	}
	expando_destroy(name, sig_perl_expando);
