#ifndef __PERL_COMMON_H
#define __PERL_COMMON_H

/* helper defines */
#define new_pv(a) \
	(newSVpv((a) == NULL ? "" : (a), (a) == NULL ? 0 : strlen(a)))

#define is_hvref(o) \
	((o) && SvROK(o) && SvRV(o) && (SvTYPE(SvRV(o)) == SVt_PVHV))

#define hvref(o) \
	(is_hvref(o) ? (HV *)SvRV(o) : NULL)

typedef void (*PERL_OBJECT_FUNC) (HV *hv, void *object);

typedef struct {
	char *name;
        PERL_OBJECT_FUNC fill_func;
} PLAIN_OBJECT_INIT_REC;

/* Returns the package who called us */
const char *perl_get_package(void);
/* Parses the package part from function name */
char *perl_function_get_package(const char *function);
/* If SV is a string, prefix it with given package.
   Increases the reference counter for the return value. */
SV *perl_func_sv_inc(SV *func, const char *package);

#ifndef pTHX_
#  define pTHX_
#endif

#ifndef aTHX_
#  define aTHX_
#endif

#define iobject_bless(object) \
	((object) == NULL ? &PL_sv_undef : \
	irssi_bless_iobject((object)->type, (object)->chat_type, object))

#define simple_iobject_bless(object) \
	((object) == NULL ? &PL_sv_undef : \
	irssi_bless_iobject((object)->type, 0, object))

#define plain_bless(object, stash) \
	((object) == NULL ? &PL_sv_undef : \
	irssi_bless_plain(stash, object))

SV *irssi_bless_iobject(int type, int chat_type, void *object);
SV *irssi_bless_plain(const char *stash, void *object);
int irssi_is_ref_object(SV *o);
void *irssi_ref_object(SV *o);

void irssi_add_object(int type, int chat_type, const char *stash,
		      PERL_OBJECT_FUNC func);
void irssi_add_plain(const char *stash, PERL_OBJECT_FUNC func);
void irssi_add_plains(PLAIN_OBJECT_INIT_REC *objects);

char *perl_get_use_list(void);

void perl_command(const char *cmd, SERVER_REC *server, WI_ITEM_REC *item);

void perl_chatnet_fill_hash(HV *hv, CHATNET_REC *chatnet);
void perl_connect_fill_hash(HV *hv, SERVER_CONNECT_REC *conn);
void perl_server_fill_hash(HV *hv, SERVER_REC *server);
void perl_window_item_fill_hash(HV *hv, WI_ITEM_REC *item);
void perl_channel_fill_hash(HV *hv, CHANNEL_REC *channel);
void perl_query_fill_hash(HV *hv, QUERY_REC *query);
void perl_nick_fill_hash(HV *hv, NICK_REC *nick);

#define irssi_boot(x) { \
	extern void boot_Irssi__##x(pTHX_ CV *cv); \
	irssi_callXS(boot_Irssi__##x, cv, mark); \
	}
void irssi_callXS(void (*subaddr)(pTHX_ CV* cv), CV *cv, SV **mark);

void perl_common_start(void);
void perl_common_stop(void);

#endif
