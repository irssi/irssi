#ifndef __PERL_COMMON_H
#define __PERL_COMMON_H

/* helper defines */
#define new_pv(a) \
	(newSVpv((a) == NULL ? "" : (a), (a) == NULL ? 0 : strlen(a)))

#define new_bless(obj, stash) \
	sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(obj))), stash)

#define push_bless(obj, stash) \
        XPUSHs(sv_2mortal(new_bless(obj, stash)))

#define is_hvref(o) \
	((o) && SvROK(o) && SvRV(o) && (SvTYPE(SvRV(o)) == SVt_PVHV))

#define hvref(o) \
	(is_hvref(o) ? (HV *)SvRV(o) : NULL)

typedef void (*PERL_OBJECT_FUNC) (HV *hv, void *object);

typedef struct {
	char *name;
        PERL_OBJECT_FUNC fill_func;
} PLAIN_OBJECT_INIT_REC;

/* returns the package who called us */
char *perl_get_package(void);

#define irssi_bless(object) \
	((object) == NULL ? &PL_sv_undef : \
	irssi_bless_iobject((object)->type, (object)->chat_type, object))
SV *irssi_bless_iobject(int type, int chat_type, void *object);
SV *irssi_bless_plain(const char *stash, void *object);
void *irssi_ref_object(SV *o);

void irssi_add_object(int type, int chat_type, const char *stash,
		      PERL_OBJECT_FUNC func);
void irssi_add_plain(const char *stash, PERL_OBJECT_FUNC func);
void irssi_add_plains(PLAIN_OBJECT_INIT_REC *objects);

char *perl_get_use_list(void);

void perl_common_init(void);
void perl_common_deinit(void);

#endif
