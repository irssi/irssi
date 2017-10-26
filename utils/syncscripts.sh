#!/bin/sh -e
# Run this script to sync dual lived scripts from scripts.irssi.org to scripts/

PKG_NAME="Irssi"

scriptbase=https://scripts.irssi.org/scripts

srcdir=`dirname "$0"`
test -z "$srcdir" && srcdir=.
srcdir="$srcdir"/..

if test ! -f "$srcdir"/configure.ac; then
    echo -n "**Error**: Directory \`$srcdir' does not look like the"
    echo " top-level $PKG_NAME directory"
    exit 1
fi

dl2='curl -Ssf'

dl_it() {
    echo "$1"
    $dl2 -o "$srcdir/scripts/$1" "$scriptbase/$1"
}

for script in \
    autoop.pl \
    autorejoin.pl \
    buf.pl \
    dns.pl \
    kills.pl \
    mail.pl \
    mlock.pl \
    quitmsg.pl \
    scriptassist.pl \
    usercount.pl \
    ;
do
    dl_it $script
done
