#!/bin/sh
# Run this to generate all the initial makefiles, etc.

PKG_NAME="Irssi"

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

if test ! -f $srcdir/irssi.cvs -a -f $srcdir/configure; then
  echo
  echo "Use ./configure instead"
  echo
  echo "This script should only be run if you got sources from SVN."
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

# create changelog
# the TZ hack is needed.
# otherwise the log will have local timezone
if test -z "$SVN"; then
	SVN=svn
fi
if $SVN --version >/dev/null 2>/dev/null; then
	if test -f $srcdir/ChangeLog; then
		CHANGELOG_VERSION=`head -n 2 $srcdir/ChangeLog| grep '^r' | sed 's/^r\([0-9]*\).*/\1/'`
	fi
	if test -z "$CHANGELOG_VERSION"; then
		echo "Getting ChangeLog from svn..."
		TZ=UTC $SVN log -v > $srcdir/ChangeLog
	else
		SVN_VERSION=`$SVN info $srcdir | grep 'Last Changed Rev' | awk '{print $4}'`
		if test -z "$SVN_VERSION"; then
			echo "**Warning**: Couldn't get svn revision number. This is probably not an svn checkout."
		else
			if test $SVN_VERSION -eq $CHANGELOG_VERSION; then
				echo ChangeLog is already up-to-date.
			else
				echo "Updating ChangeLog from version $CHANGELOG_VERSION to $SVN_VERSION..."
				mv $srcdir/ChangeLog $srcdir/ChangeLog.prev
				TZ=UTC $SVN log -v --incremental $srcdir -r $SVN_VERSION:`expr $CHANGELOG_VERSION + 1` > $srcdir/ChangeLog
				cat $srcdir/ChangeLog.prev >> $srcdir/ChangeLog
			fi
		fi
	fi
else
	if test -f $srcdir/ChangeLog; then
		echo "**Warning**: svn not found, skipping ChangeLog updating. The reported irssi version may be incorrect."
	else
		echo "**Error**: svn not found, and ChangeLog file missing, can not determine version."
		exit 1
	fi
fi

files=`echo docs/help/in/*.in|sed -e 's,docs/help/in/Makefile.in ,,' -e 's,docs/help/in/,!,g' -e 's/\.in /.in ?/g'`
cat docs/help/in/Makefile.am.gen|sed "s/@HELPFILES@/$files/g"|sed 's/?/\\?/g'|tr '!?' '\t\n' > docs/help/in/Makefile.am

files=`echo $files|sed 's/\.in//g'`
cat docs/help/Makefile.am.gen|sed "s/@HELPFILES@/$files/g"|sed 's/?/\\?/g'|tr '!?' '\t\n' > docs/help/Makefile.am

# .html -> .txt with lynx
echo "Documentation: html -> txt..."
lynx -dump -nolist docs/faq.html|perl -pe 's/^ *//; if ($_ eq "\n" && $state eq "Q") { $_ = ""; } elsif (/^([QA]):/) { $state = $1 } elsif ($_ ne "\n") { $_ = "   $_"; };' > docs/faq.txt

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
