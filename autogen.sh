#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

PKG_NAME="Irssi"

(test -f $srcdir/configure.in \
## put other tests here
) || {
    echo -n "**Error**: Directory "\`$srcdir\'" does not look like the"
    echo " top-level $PKG_NAME directory"
    exit 1
}

# get versions

version=`cat configure.in|grep AM_INIT_AUTOMAKE|sed 's/[^,]*, \([^\)]*\).*/\1/'`
version_date=`date +%Y%m%d`

echo "/* automatically created by autogen.sh */" > irssi-version.h
echo "#define IRSSI_VERSION \"$version\"" >> irssi-version.h
echo "#define IRSSI_VERSION_DATE \"$version_date\"" >> irssi-version.h

. $srcdir/macros/autogen.sh
