#! /bin/sh

srcdir=$1
test -d $srcdir/.svn || exit
SVN_VERSION=`LC_ALL=C svn info $srcdir 2>/dev/null | awk '/^Last Changed Rev/{print $4}'`
test -n "$SVN_VERSION" || exit
if test -f $srcdir/ChangeLog; then
	CHANGELOG_VERSION=`awk 'NR == 2{print substr($1, 2);exit}' $srcdir/ChangeLog`
fi
if test -z "$CHANGELOG_VERSION"; then
	TZ=UTC svn log -v $srcdir > $srcdir/ChangeLog
elif test $SVN_VERSION -ne $CHANGELOG_VERSION; then
	TZ=UTC svn log -v --incremental -r $SVN_VERSION:`expr $CHANGELOG_VERSION + 1` $srcdir | \
	cat - $srcdir/ChangeLog > ChangeLog.$$ && mv ChangeLog.$$ $srcdir/ChangeLog
fi
