#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

# I'm too lazy to update version number into several places.. :)
version=`cat configure.in|grep AM_INIT_AUTOMAKE|perl -pe 's/^[^,]*,[ ]*([^\)]*).*/$1/'`
cat irssi.spec.in |sed s/^Version:/Version:\ $version/ > irssi.spec

PKG_NAME="Irssi"

(test -f $srcdir/configure.in \
## put other tests here
) || {
    echo -n "**Error**: Directory "\`$srcdir\'" does not look like the"
    echo " top-level $PKG_NAME directory"
    exit 1
}

. $srcdir/macros/autogen.sh
