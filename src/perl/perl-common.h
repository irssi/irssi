#ifndef __PERL_COMMON_H
#define __PERL_COMMON_H

#define new_pv(a) \
	(newSVpv((a) == NULL ? "" : (a), (a) == NULL ? 0 : strlen(a)))

#define new_bless(obj, stash) \
	sv_bless(newRV_noinc(newSViv(GPOINTER_TO_INT(obj))), stash)

#define is_hvref(o) \
	((o) && SvROK(o) && SvRV(o) && (SvTYPE(SvRV(o)) == SVt_PVHV))

#define hvref(o) \
	(is_hvref(o) ? (HV *)SvRV(o) : NULL)

#define push_bless(obj, stash) \
        XPUSHs(sv_2mortal(new_bless(obj, stash)))

#define irssi_bless(object) \
	irssi_bless_object((object)->type, (object)->chat_type, object)

/* returns the package who called us */
char *perl_get_package(void);

SV *irssi_bless_object(int type, int chat_type, void *object);
void *irssi_ref_object(SV *o);

void irssi_add_object(int type, int chat_type, const char *stash);

void perl_common_init(void);
void perl_common_deinit(void);

#endif
