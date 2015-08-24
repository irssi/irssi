#!/bin/sh
# Run this to generate all the initial makefiles, etc.

PKG_NAME="Irssi"

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

if test ! -f $srcdir/configure.ac; then
    echo -n "**Error**: Directory \`$srcdir\' does not look like the"
    echo " top-level $PKG_NAME directory"
    exit 1
fi

# create help files
echo "Creating help files..."
perl syntax.pl

echo "Creating ChangeLog..."
git log > $srcdir/ChangeLog
if test "$?" -ne 0; then
    echo "**Error**: ${PKG_NAME} Autogen must be run in a git clone, cannot proceed."
    exit 1
fi

files=`echo docs/help/in/*.in|sed -e 's,docs/help/in/Makefile.in ,,' -e 's,docs/help/in/,!,g' -e 's/\.in /.in ?/g'`
cat docs/help/in/Makefile.am.gen|sed "s/@HELPFILES@/$files/g"|sed 's/?/\\?/g'|tr '!?' '\t\n' > docs/help/in/Makefile.am

files=`echo $files|sed 's/\.in//g'`
cat docs/help/Makefile.am.gen|sed "s/@HELPFILES@/$files/g"|sed 's/?/\\?/g'|tr '!?' '\t\n' > docs/help/Makefile.am

# .html -> .txt with lynx or elinks
echo "Documentation: html -> txt..."
if type lynx >/dev/null 2>&1 ; then
  LC_ALL=C lynx -dump docs/faq.html|perl -pe 's/^ *//; if ($_ eq "\n" && $state eq "Q") { $_ = ""; } elsif (/^([QA]):/) { $state = $1 } elsif ($_ ne "\n") { $_ = "   $_"; };' > docs/faq.txt
elif type elinks >/dev/null 2>&1 ; then
  elinks -dump docs/faq.html|perl -pe 's/^ *//; if ($_ eq "\n" && $state eq "Q") { $_ = ""; } elsif (/^([QA]):/) { $state = $1 } elsif ($_ ne "\n") { $_ = "   $_"; };' > docs/faq.txt
elif type links >/dev/null 2>&1 ; then
  links -dump docs/faq.html|perl -pe 's/^ *//; if ($_ eq "\n" && $state eq "Q") { $_ = ""; } elsif (/^([QA]):/) { $state = $1 } elsif ($_ ne "\n") { $_ = "   $_"; };' > docs/faq.txt
else
  echo "**Error**: No lynx or elinks present"
  exit 1
fi

if test x$NOCONFIGURE = x && test -z "$*"; then
  echo "**Warning**: I am going to run \`configure' with no arguments."
  echo "If you wish to pass any to it, please specify them on the"
  echo \`$0\'" command line."
  echo
fi

rm -f aclocal.m4
echo "Running autoreconf ..."
autoreconf -i || exit 1

conf_flags="--enable-maintainer-mode"

if test x$NOCONFIGURE = x; then
  echo Running $srcdir/configure $conf_flags "$@" ...
  $srcdir/configure $conf_flags "$@" \
  && echo Now type \`make\' to compile $PKG_NAME || exit 1
else
  echo Skipping configure process.
fi

# make sure perl hashes have correct length
find src/perl -name *.c -o -name *.xs | xargs grep -n hv_store | perl -ne 'if (/"(\w+)",\s*(\d+)/) { print unless $2 == length $1 }'
