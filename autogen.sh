#!/bin/sh
# Run this to generate all the initial makefiles, etc.

PKG_NAME="Irssi"

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

if test ! -f $srcdir/irssi.cvs -a -f $srcdir/configure; then
  echo
  echo "Use ./configure instead"
  echo
  echo "This script should only be run if you got sources from CVS."
  echo "If you really want to do this, say:"
  echo "  touch irssi.cvs"
  exit 0
fi

if test ! -f $srcdir/configure.in; then
    echo -n "**Error**: Directory \`$srcdir\' does not look like the"
    echo " top-level $PKG_NAME directory"
    exit 1
fi

# get versions
version_date=`date +%Y%m%d`

# create help files
echo "Creating help files..."
perl syntax.pl

files=`echo docs/help/in/*.in|sed -e 's,docs/help/in/Makefile.in ,,' -e 's,docs/help/in/,!,g' -e 's/\.in /.in ?/g'`
cat docs/help/in/Makefile.am.gen|sed "s/@HELPFILES@/$files/g"|sed 's/?/\\?/g'|tr '!?' '\t\n' > docs/help/in/Makefile.am

files=`echo $files|sed 's/\.in//g'`
cat docs/help/Makefile.am.gen|sed "s/@HELPFILES@/$files/g"|sed 's/?/\\?/g'|tr '!?' '\t\n' > docs/help/Makefile.am

# .html -> .txt with lynx
echo "Documentation: html -> txt..."
lynx -dump -nolist docs/faq.html|perl -pe 's/^ *//; if ($_ eq "\n" && $state eq "Q") { $_ = ""; } elsif (/^([QA]):/) { $state = $1 } elsif ($_ ne "\n") { $_ = "   $_"; };' > docs/faq.txt

echo "Checking auto* tools..."

# *********** a bit modified GNOME's macros/autogen.sh **********
DIE=0

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Error**: You must have \`autoconf' installed to compile $PKG_NAME."
  echo "Download the appropriate package for your distribution,"
  echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/"
  DIE=1
}

(grep "^AM_PROG_LIBTOOL" $srcdir/configure.in >/dev/null) && {
  (libtool --version) < /dev/null > /dev/null 2>&1 || {
    echo
    echo "**Error**: You must have \`libtool' installed to compile $PKG_NAME."
    echo "Get ftp://ftp.gnu.org/pub/gnu/libtool-1.2d.tar.gz"
    echo "(or a newer version if it is available)"
    DIE=1
  }
}

(automake --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Error**: You must have \`automake' installed to compile $PKG_NAME."
  echo "Get ftp://ftp.gnu.org/pub/gnu/automake-1.3.tar.gz"
  echo "(or a newer version if it is available)"
  DIE=1
  NO_AUTOMAKE=yes
}


# if no automake, don't bother testing for aclocal
test -n "$NO_AUTOMAKE" || (aclocal --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Error**: Missing \`aclocal'.  The version of \`automake'"
  echo "installed doesn't appear recent enough."
  echo "Get ftp://ftp.gnu.org/pub/gnu/automake-1.3.tar.gz"
  echo "(or a newer version if it is available)"
  DIE=1
}

if test "$DIE" -eq 1; then
  exit 1
fi

if test -z "$*"; then
  echo "**Warning**: I am going to run \`configure' with no arguments."
  echo "If you wish to pass any to it, please specify them on the"
  echo \`$0\'" command line."
  echo
fi

case $CC in
xlc )
  am_opt=--include-deps;;
esac

rm -f aclocal.m4 glib.m4 glib-2.0.m4
if grep "^AM_PROG_LIBTOOL" configure.in >/dev/null; then
  echo "Running libtoolize..."
  libtoolize --force --copy
fi
aclocalinclude="$ACLOCAL_FLAGS -I ."
echo "Running aclocal $aclocalinclude ..."

# see if we don't have glib.m4 or glib-2.0.m4 there yet
error=`aclocal $aclocalinclude 2>&1`
if test "x`echo $error|grep 'AM_PATH_GLIB[^_]'`" != "x"; then
  cp glib.m4_ glib.m4
  error=`aclocal $aclocalinclude 2>&1`
fi
if test "x`echo $error|grep AM_PATH_GLIB_2_0`" != "x"; then
  cp glib-2.0.m4_ glib-2.0.m4
fi

aclocal $aclocalinclude

# aclocal for some reason doesn't complain about glib2, so we still need
# to check it later again..
if grep "^AC_DEFUN.AM_PATH_GLIB_2_0" aclocal.m4 >/dev/null; then :;
else
  cp glib-2.0.m4_ glib-2.0.m4
  aclocal $aclocalinclude
fi

if grep "^AM_CONFIG_HEADER" configure.in >/dev/null; then
  echo "Running autoheader..."
  autoheader
fi
echo "Running autoconf ..."
autoconf
echo "Running automake --gnu $am_opt ..."
automake --add-missing --gnu $am_opt

conf_flags="--enable-maintainer-mode --enable-compile-warnings" #--enable-iso-c

if test x$NOCONFIGURE = x; then
  echo Running $srcdir/configure $conf_flags "$@" ...
  $srcdir/configure $conf_flags "$@" \
  && echo Now type \`make\' to compile $PKG_NAME || exit 1
else
  echo Skipping configure process.
fi

# make sure perl hashes have correct length
find src/perl -name *.c -o -name *.xs | xargs grep -n hv_store | perl -ne 'if (/"(\w+)",\s*(\d+)/) { print unless $2 == length $1 }'
