#ifdef ENABLE_NLS
#  ifdef HAVE_LIBINTL_H
#    include <libintl.h>
#  else
#    include "../intl/libgettext.h"
#  endif
#  define _(String) gettext (String)
#  ifdef gettext_noop
#    define N_(String) gettext_noop (String)
#  else
#    define N_(String) (String)
#  endif
#  ifdef HAVE_LANGINFO_H
#    include <langinfo.h>
#  else
#    define nl_langinfo(x) x
#    define YESEXPR 'Y'
#  endif
#else
/* Stubs that do something close enough.  */
#  define textdomain(String) (String)
#  define gettext(String) (String)
#  define dgettext(Domain,Message) (Message)
#  define dcgettext(Domain,Message,Type) (Message)
#  define bindtextdomain(Domain,Directory) (Domain)
#  define _(String) (String)
#  define N_(String) (String)
#endif
