#include <EXTERN.h>
#ifndef _SEM_SEMUN_UNDEFINED
#define HAS_UNION_SEMUN
#endif
#include <perl.h>

#undef _
#undef PACKAGE

/* For compatibility with perl 5.004 and older */
#ifndef ERRSV
#  define ERRSV GvSV(errgv)
#endif

#include "common.h"

#define MODULE_NAME "irssi-perl"
