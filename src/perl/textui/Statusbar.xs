#include "module.h"

static GHashTable *perl_sbar_defs;

static int check_sbar_destroy(char *key, char *value, char *script)
{
	if (strncmp(value, script, strlen(script)) == 0 &&
	    value[strlen(script)] == ':') {
                statusbar_item_unregister(key);
		g_free(key);
                g_free(value);
		return TRUE;
	}

        return FALSE;
}

static void script_unregister_statusbars(PERL_SCRIPT_REC *script)
{
	g_hash_table_foreach_remove(perl_sbar_defs,
				    (GHRFunc) check_sbar_destroy,
				    script->package);
}

void perl_statusbar_init(void)
{
	perl_sbar_defs = g_hash_table_new((GHashFunc) g_str_hash,
					  (GCompareFunc) g_str_equal);
	signal_add("script destroyed", (SIGNAL_FUNC) script_unregister_statusbars);
}

static void statusbar_item_def_destroy(void *key, void *value)
{
	statusbar_item_unregister(key);
	g_free(key);
        g_free(value);
}

void perl_statusbar_deinit(void)
{
	signal_remove("script destroyed", (SIGNAL_FUNC) script_unregister_statusbars);

	g_hash_table_foreach(perl_sbar_defs,
			     (GHFunc) statusbar_item_def_destroy, NULL);
	g_hash_table_destroy(perl_sbar_defs);
}

static void perl_statusbar_event(char *function, SBAR_ITEM_REC *item,
				 int get_size_only)
{
	dSP;
	int retcount;
	SV *item_sv, **sv;
        HV *hv;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
        item_sv = plain_bless(item, "Irssi::TextUI::StatusbarItem");
	XPUSHs(sv_2mortal(item_sv));
	XPUSHs(sv_2mortal(newSViv(get_size_only)));
	PUTBACK;

	retcount = perl_call_pv(function, G_EVAL|G_DISCARD);
	SPAGAIN;

	if (SvTRUE(ERRSV)) {
                PERL_SCRIPT_REC *script;
                char *package;

                package = perl_function_get_package(function);
                script = perl_script_find_package(package);
                g_free(package);

		if (script != NULL) {
                        /* make sure we don't get back here */
			script_unregister_statusbars(script);
		}
		signal_emit("script error", 2, script, SvPV(ERRSV, PL_na));
	} else {
		/* min_size and max_size can be changed, move them to SBAR_ITEM_REC */
		hv = hvref(item_sv);
		if (hv != NULL) {
			sv = hv_fetch(hv, "min_size", 8, 0);
			if (sv != NULL) item->min_size = SvIV(*sv);
			sv = hv_fetch(hv, "max_size", 8, 0);
			if (sv != NULL) item->max_size = SvIV(*sv);
		}
	}

	PUTBACK;
	FREETMPS;
	LEAVE;
}


static void sig_perl_statusbar(SBAR_ITEM_REC *item, int get_size_only)
{
	char *function;

	function = g_hash_table_lookup(perl_sbar_defs, item->config->name);
	if (function != NULL)
		perl_statusbar_event(function, item, get_size_only);
	else {
		/* use default function - this shouldn't actually happen.. */
		statusbar_item_default_handler(item, get_size_only, NULL, "", TRUE);
	}
}

MODULE = Irssi::TextUI::Statusbar  PACKAGE = Irssi
PROTOTYPES: ENABLE

void
statusbar_item_register(name, value, func = NULL)
	char *name
	char *value
	char *func
CODE:
	statusbar_item_register(name, value, func == NULL || *func == '\0' ? NULL : sig_perl_statusbar);
	if (func != NULL) {
		g_hash_table_insert(perl_sbar_defs, g_strdup(name),
				    g_strdup_printf("%s::%s", perl_get_package(), func));
	}

void
statusbar_item_unregister(name)
	char *name
PREINIT:
        gpointer key, value;
CODE:
	if (g_hash_table_lookup_extended(perl_sbar_defs, name, &key, &value)) {
                g_hash_table_remove(perl_sbar_defs, name);
		g_free(key);
                g_free(value);
	}
	statusbar_item_unregister(name);

void
statusbar_items_redraw(name)
	char *name

void
statusbars_recreate_items()

#*******************************
MODULE = Irssi::TextUI::Statusbar  PACKAGE = Irssi::TextUI::StatusbarItem  PREFIX = statusbar_item_
#*******************************

void
statusbar_item_default_handler(item, get_size_only, str, data, escape_vars = TRUE)
	Irssi::TextUI::StatusbarItem item
	int get_size_only
	char *str
	char *data
	int escape_vars
PREINIT:
	HV *hv;
CODE:
	statusbar_item_default_handler(item, get_size_only,
				       *str == '\0' ? NULL : str,
				       data, escape_vars);
	hv = hvref(ST(0));
	hv_store(hv, "min_size", 8, newSViv(item->min_size), 0);
	hv_store(hv, "max_size", 8, newSViv(item->max_size), 0);
