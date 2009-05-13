#! /bin/sh

if test -d "$1"/.svn ; then
	DATE=`LC_ALL=C svn info "$1" | sed -n 's/^Last Changed Date: \(.*\)/\1/p'`
elif test -d "$1"/.git ; then
	DATE=`GIT_DIR=$1/.git git log -1 --pretty=format:%ai HEAD`
else
	DATE=`awk -F'|' 'NR == 2{print substr($3, 2)}' "$1"/ChangeLog`
fi
VERSION_DATE=`echo $DATE | cut -f 1 -d ' ' | tr -d -`
VERSION_TIME=`echo $DATE | cut -f 2 -d ' ' | awk -F: '{printf "%d", $1$2}'`
echo "#define IRSSI_VERSION_DATE $VERSION_DATE"
echo "#define IRSSI_VERSION_TIME $VERSION_TIME"
