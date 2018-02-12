#!/bin/sh
# Run this to generate all the initial makefiles, etc.

PKG_NAME="Irssi"

srcdir=`dirname "$0"`
test -z "$srcdir" && srcdir=.
mydir=`pwd`

if test ! -f "$srcdir"/configure.ac; then
    echo -n "**Error**: Directory \`$srcdir' does not look like the"
    echo " top-level $PKG_NAME directory"
    exit 1
fi

cd "$srcdir"

# create help files
echo "Creating help files..."
perl utils/syntax.pl

echo "Creating ChangeLog..."
git log > ChangeLog
if test "$?" -ne 0; then
    echo "**Error**: ${PKG_NAME} Autogen must be run in a git clone, cannot proceed."
    exit 1
fi

files=`echo docs/help/in/*.in|sed -e 's,docs/help/in/Makefile.in ,,' -e 's,docs/help/in/,!,g' -e 's/\.in /.in ?/g'`
cat docs/help/in/Makefile.am.gen|sed "s/@HELPFILES@/$files/g"|sed 's/?/\\?/g'|tr '!?' '\t\n' > docs/help/in/Makefile.am

files=`echo $files|sed 's/\.in//g'`
cat docs/help/Makefile.am.gen|sed "s/@HELPFILES@/$files/g"|sed 's/?/\\?/g'|tr '!?' '\t\n' > docs/help/Makefile.am

if test x$NOCONFIGURE = x && test -z "$*"; then
  echo "**Warning**: I am going to run \`configure' with no arguments."
  echo "If you wish to pass any to it, please specify them on the"
  echo \`$0\'" command line."
  echo
fi

rm -f aclocal.m4
echo "Running autoreconf ..."
autoreconf -i || exit $?

# make sure perl hashes have correct length
find src/perl -name '*.c' -o -name '*.xs' -exec grep -n hv_store {} + | perl -l -ne 'if (/"(\w+)",\s*(\d+)/ && $2 != length $1) { $X=1; print "Incorrect key length in $_" } END { exit $X }'

cd "$mydir"

conf_flags="--enable-maintainer-mode"

if test x$NOCONFIGURE = x; then
  echo Running "$srcdir"/configure $conf_flags "$@" ...
  "$srcdir"/configure $conf_flags "$@" \
  && echo Now type \`make\' to compile $PKG_NAME || exit 1
else
  echo Skipping configure process.
fi

if grep -q '==\|\[\[' "$srcdir"/build-aux/test-driver; then
    echo
    echo "************************************************************************"
    echo "**Warning**: your build is not portable, please do not make dist"
    echo "             see https://bugzilla.opensuse.org/show_bug.cgi?id=1076146"
    echo "************************************************************************"
fi
