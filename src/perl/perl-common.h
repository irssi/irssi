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

/* For compatibility with perl 5.004 and older */
#ifndef HAVE_PL_PERL
#  define PL_sv_undef sv_undef
#endif

#define irssi_bless(object) \
	((object) == NULL ? &PL_sv_undef : \
	irssi_bless_iobject((object)->type, (object)->chat_type, object))

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

void perl_common_start(void);
void perl_common_stop(void);

#endif
