#include "module.h"
#include "modules.h"
#include "signals.h"
#include "commands.h"
#include "servers.h"

#include "perl-common.h"

typedef struct {
	int signal_id;
	char *signal;

	char *func;
	int priority;
} PERL_SIGNAL_REC;

typedef struct {
	int signal_id;
	char *signal;
	char *args[7];
} PERL_SIGNAL_ARGS_REC;

#include "perl-signals-list.h"

static GHashTable *signals[3];
static GHashTable *perl_signal_args_hash;
static GSList *perl_signal_args_partial;

static PERL_SIGNAL_ARGS_REC *perl_signal_args_find(int signal_id)
{
	PERL_SIGNAL_ARGS_REC *rec;
        GSList *tmp;
	const char *signame;

	rec = g_hash_table_lookup(perl_signal_args_hash,
				  GINT_TO_POINTER(signal_id));
        if (rec != NULL) return rec;

	/* try to find by name */
	signame = signal_get_id_str(signal_id);
	for (tmp = perl_signal_args_partial; tmp != NULL; tmp = tmp->next) {
		rec = tmp->data;

		if (strncmp(rec->signal, signame, strlen(rec->signal)) == 0)
			return rec;
	}

	return NULL;
}

static int perl_call_signal(const char *func, int signal_id,
			    gconstpointer *args)
{
	dSP;
	int retcount, ret;

	PERL_SIGNAL_ARGS_REC *rec;
	HV *stash;
	SV *perlarg;
        void *arg;
	int n;


	ENTER;
	SAVETMPS;

	PUSHMARK(sp);

	/* push signal argument to perl stack */
	rec = perl_signal_args_find(signal_id);

	for (n = 0; n < SIGNAL_MAX_ARGUMENTS &&
		    rec != NULL && rec->args[n] != NULL; n++) {
		arg = (void *) args[n];

		if (strcmp(rec->args[n], "string") == 0)
			perlarg = new_pv(arg);
		else if (strcmp(rec->args[n], "int") == 0)
			perlarg = newSViv(GPOINTER_TO_INT(arg));
		else if (strcmp(rec->args[n], "ulongptr") == 0)
			perlarg = newSViv(*(unsigned long *) arg);
		else if (strncmp(rec->args[n], "gslist_", 7) == 0) {
			/* linked list - push as AV */
			GSList *tmp;
			AV *av;

			av = newAV();
			stash = gv_stashpv(rec->args[n]+7, 0);
			for (tmp = arg; tmp != NULL; tmp = tmp->next)
				av_push(av, sv_2mortal(new_bless(tmp->data, stash)));
			perlarg = (SV*)av;
		} else if (arg == NULL) {
			/* don't bless NULL arguments */
			perlarg = newSViv(0);
		} else if (strcmp(rec->args[n], "iobject") == 0) {
			/* "irssi object" - any struct that has
			   "int type; int chat_type" as its first
			   variables (server, channel, ..) */
			perlarg = irssi_bless((SERVER_REC *) arg);
		} else {
			/* blessed object */
			perlarg = irssi_bless_plain(rec->args[n], arg);
		}
                XPUSHs(sv_2mortal(perlarg));
	}

	PUTBACK;
	retcount = perl_call_pv((char *) func, G_EVAL|G_SCALAR);
	SPAGAIN;

	ret = 0;
	if (SvTRUE(ERRSV)) {
		STRLEN n_a;

		signal_emit("gui dialog", 2, "error", SvPV(ERRSV, n_a));
		(void)POPs;
	} else if (retcount > 0) {
		SV *sv = POPs;

		if (SvIOK(sv) && SvIV(sv) == 1) ret = 1;
		while (--retcount > 0)
			(void)POPi;
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return ret;
}

static void sig_func(int priority, gconstpointer *args)
{
	GSList **list, *tmp;
        int signal_id;

        signal_id = signal_get_emitted_id();
	list = g_hash_table_lookup(signals[priority],
				   GINT_TO_POINTER(signal_id));
	for (tmp = list == NULL ? NULL : *list; tmp != NULL; tmp = tmp->next) {
		PERL_SIGNAL_REC *rec = tmp->data;

		if (perl_call_signal(rec->func, signal_id, args)) {
			signal_stop();
			break;
		}
	}
}

#define SIG_FUNC_DECL(priority, priority_name) \
static void sig_func_##priority_name(gconstpointer p1, gconstpointer p2, \
				     gconstpointer p3, gconstpointer p4, \
				     gconstpointer p5, gconstpointer p6) \
{ \
	gconstpointer args[6]; \
        args[0] = p1; args[1] = p2; args[2] = p3; \
        args[3] = p4; args[4] = p5; args[5] = p6; \
        sig_func(priority, args); \
}

SIG_FUNC_DECL(0, first);
SIG_FUNC_DECL(1, default);
SIG_FUNC_DECL(2, last);

#define perl_signal_get_func(rec) \
	((rec)->priority == 0 ? sig_func_first : \
	(rec)->priority == 1 ? sig_func_default : sig_func_last)

void perl_signal_add_to(const char *signal, const char *func, int priority)
{
	PERL_SIGNAL_REC *rec;
	GHashTable *table;
	GSList **siglist;
	void *signal_idp;

        g_return_if_fail(signal != NULL);
        g_return_if_fail(func != NULL);
        g_return_if_fail(priority >= 0 && priority <= 2);

	rec = g_new(PERL_SIGNAL_REC, 1);
	rec->signal_id = signal_get_uniq_id(signal);
	rec->signal = g_strdup(signal);
	rec->func = g_strdup_printf("%s::%s", perl_get_package(), func);
	rec->priority = priority;

	table = signals[priority];
	signal_idp = GINT_TO_POINTER(rec->signal_id);

	siglist = g_hash_table_lookup(table, signal_idp);
	if (siglist == NULL) {
		siglist = g_new0(GSList *, 1);
		g_hash_table_insert(table, signal_idp, siglist);

		signal_add_to_id(MODULE_NAME, priority, rec->signal_id,
                                 perl_signal_get_func(rec));
	}

	*siglist = g_slist_append(*siglist, rec);
}

static void perl_signal_destroy(PERL_SIGNAL_REC *rec)
{
	if (strncmp(rec->signal, "command ", 8) == 0)
		command_unbind(rec->signal+8, NULL);

	g_free(rec->signal);
	g_free(rec->func);
	g_free(rec);
}

static void perl_signal_remove_list_one(GSList **siglist, PERL_SIGNAL_REC *rec)
{
	void *signal_idp;

	g_return_if_fail(rec != NULL);

	signal_idp = GINT_TO_POINTER(rec->signal_id);

	*siglist = g_slist_remove(*siglist, rec);
	if (*siglist == NULL) {
		signal_remove_id(rec->signal_id, perl_signal_get_func(rec));
		g_free(siglist);
		g_hash_table_remove(signals[rec->priority], signal_idp);
	}

        perl_signal_destroy(rec);
}

static void perl_signal_remove_list(GSList **list, const char *func)
{
	GSList *tmp;

	g_return_if_fail(list != NULL);

	for (tmp = *list; tmp != NULL; tmp = tmp->next) {
		PERL_SIGNAL_REC *rec = tmp->data;

		if (strcmp(func, rec->func) == 0) {
			perl_signal_remove_list_one(list, rec);
			break;
		}
	}
}

void perl_signal_remove(const char *signal, const char *func)
{
	GSList **list;
        void *signal_idp;
	char *fullfunc;
	int n;

	signal_idp = GINT_TO_POINTER(signal_get_uniq_id(signal));

	fullfunc = g_strdup_printf("%s::%s", perl_get_package(), func);
	for (n = 0; n < sizeof(signals)/sizeof(signals[0]); n++) {
		list = g_hash_table_lookup(signals[n], signal_idp);
		if (list != NULL)
			perl_signal_remove_list(list, func);
	}
	g_free(fullfunc);
}

static int signal_destroy_hash(void *key, GSList **list, const char *package)
{
	GSList *tmp, *next;
	int len;

	len = package == NULL ? 0 : strlen(package);
	for (tmp = *list; tmp != NULL; tmp = next) {
		PERL_SIGNAL_REC *rec = tmp->data;

		next = tmp->next;
		if (package != NULL && strncmp(rec->func, package, len) != 0)
                        continue;

		*list = g_slist_remove(*list, rec);
		if (*list == NULL) {
			signal_remove_id(rec->signal_id,
					 perl_signal_get_func(rec));
		}
		perl_signal_destroy(rec);
	}

	if (*list != NULL)
		return FALSE;

	g_free(list);
	return TRUE;
}

/* destroy all signals used by package */
void perl_signals_package_destroy(const char *package)
{
	int n;

	for (n = 0; n < sizeof(signals)/sizeof(signals[0]); n++) {
		g_hash_table_foreach_remove(signals[n],
					    (GHRFunc) signal_destroy_hash,
					    (void *) package);
	}
}

void perl_signals_start(void)
{
	int n;

	for (n = 0; n < sizeof(signals)/sizeof(signals[0]); n++) {
		signals[n] = g_hash_table_new((GHashFunc) g_direct_hash,
					      (GCompareFunc) g_direct_equal);
	}
}

void perl_signals_stop(void)
{
	int n;

	for (n = 0; n < sizeof(signals)/sizeof(signals[0]); n++) {
		g_hash_table_foreach(signals[n],
				     (GHFunc) signal_destroy_hash, NULL);
		g_hash_table_destroy(signals[n]);
	}
}

void perl_signals_init(void)
{
	int n;

	perl_signal_args_hash = g_hash_table_new((GHashFunc) g_direct_hash,
						 (GCompareFunc) g_direct_equal);
        perl_signal_args_partial = NULL;

	for (n = 0; perl_signal_args[n].signal != NULL; n++) {
		PERL_SIGNAL_ARGS_REC *rec = &perl_signal_args[n];

		if (rec->signal[strlen(rec->signal)-1] == ' ') {
			perl_signal_args_partial =
				g_slist_append(perl_signal_args_partial, rec);
		} else {
			g_hash_table_insert(perl_signal_args_hash,
					    GINT_TO_POINTER(rec->signal_id),
					    rec);
		}
	}
}

void perl_signals_deinit(void)
{
        g_slist_free(perl_signal_args_partial);
        g_hash_table_destroy(perl_signal_args_hash);
}
