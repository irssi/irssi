dnl
dnl  Off-the-Record Messaging library
dnl  Copyright (C) 2004-2007  Ian Goldberg, Chris Alexander, Nikita Borisov
dnl                           <otr@cypherpunks.ca>
dnl
dnl  This library is free software; you can redistribute it and/or
dnl  modify it under the terms of version 2.1 of the GNU Lesser General
dnl  Public License as published by the Free Software Foundation.
dnl
dnl  This library is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl  Lesser General Public License for more details.
dnl
dnl  You should have received a copy of the GNU Lesser General Public
dnl  License along with this library; if not, write to the Free Software
dnl  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
dnl

dnl AM_PATH_LIBOTR([MINIMUM-VERSION [, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for libotr, and define LIBOTR_CFLAGS and LIBOTR_LIBS as appropriate.
dnl enables arguments --with-libotr-prefix=
dnl                   --with-libotr-inc-prefix=
dnl
dnl You must already have found libgcrypt with AM_PATH_LIBGCRYPT
dnl
dnl Adapted from alsa.m4, originally by
dnl      Richard Boulton <richard-alsa@tartarus.org>
dnl      Christopher Lansdown <lansdoct@cs.alfred.edu>
dnl      Jaroslav Kysela <perex@suse.cz>

AC_DEFUN([AM_PATH_LIBOTR],
[dnl Save the original CFLAGS, LDFLAGS, and LIBS
libotr_save_CFLAGS="$CFLAGS"
libotr_save_LDFLAGS="$LDFLAGS"
libotr_save_LIBS="$LIBS"
libotr_found=yes

dnl
dnl Get the cflags and libraries for libotr
dnl
AC_ARG_WITH(libotr-prefix,
[  --with-libotr-prefix=PFX  Prefix where libotr is installed(optional)],
[libotr_prefix="$withval"], [libotr_prefix=""])

AC_ARG_WITH(libotr-inc-prefix,
[  --with-libotr-inc-prefix=PFX  Prefix where libotr includes are (optional)],
[libotr_inc_prefix="$withval"], [libotr_inc_prefix=""])

dnl Add any special include directories
AC_MSG_CHECKING(for libotr CFLAGS)
if test "$libotr_inc_prefix" != "" ; then
	LIBOTR_CFLAGS="$LIBOTR_CFLAGS -I$libotr_inc_prefix"
	CFLAGS="$CFLAGS $LIBOTR_CFLAGS"
fi
AC_MSG_RESULT($LIBOTR_CFLAGS)

dnl add any special lib dirs
AC_MSG_CHECKING(for libotr LIBS)
if test "$libotr_prefix" != "" ; then
	LIBOTR_LIBS="$LIBOTR_LIBS -L$libotr_prefix"
	LDFLAGS="$LDFLAGS $LIBOTR_LIBS"
fi

dnl add the libotr library
LIBOTR_LIBS="$LIBOTR_LIBS -lotr"
LIBS="$LIBOTR_LIBS $LIBS"
AC_MSG_RESULT($LIBOTR_LIBS)

dnl Check for a working version of libotr that is of the right version.
min_libotr_version=ifelse([$1], ,3.0.0,$1)
no_libotr=""
    libotr_min_major_version=`echo $min_libotr_version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\1/'`
    libotr_min_minor_version=`echo $min_libotr_version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\2/'`
    libotr_min_sub_version=`echo $min_libotr_version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\3/'`
AC_MSG_CHECKING(for libotr headers version $libotr_min_major_version.x >= $min_libotr_version)

AC_LANG_SAVE
AC_LANG_C
AC_TRY_COMPILE([
#include <stdlib.h>
#include <libotr/version.h>
], [
#  if(OTRL_VERSION_MAJOR != $libotr_min_major_version)
#    error not present
#  else

#    if(OTRL_VERSION_MINOR > $libotr_min_minor_version)
       exit(0);
#    else
#      if(OTRL_VERSION_MINOR < $libotr_min_minor_version)
#        error not present
#      endif

#      if(OTRL_VERSION_SUB < $libotr_min_sub_version)
#        error not present
#      endif
#    endif
#  endif
exit(0);
],
  [AC_MSG_RESULT(found.)],
  [AC_MSG_RESULT(not present.)
   ifelse([$3], , [AC_MSG_ERROR(Sufficiently new version of libotr not found.)])
   libotr_found=no]
)
AC_LANG_RESTORE

dnl Now that we know that we have the right version, let's see if we have the library and not just the headers.
AC_CHECK_LIB([otr], [otrl_message_receiving],,
	[ifelse([$3], , [AC_MSG_ERROR(No linkable libotr was found.)])
	 libotr_found=no],
	 $LIBGCRYPT_LIBS
)

LDFLAGS="$libotr_save_LDFLAGS"
LIBS="$libotr_save_LIBS"

if test "x$libotr_found" = "xyes" ; then
   ifelse([$2], , :, [$2])
else
   LIBOTR_CFLAGS=""
   LIBOTR_LIBS=""
   ifelse([$3], , :, [$3])
fi

dnl That should be it.  Now just export our symbols:
AC_SUBST(LIBOTR_CFLAGS)
AC_SUBST(LIBOTR_LIBS)
])

