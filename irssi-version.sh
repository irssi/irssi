#!/bin/sh

DATE=`GIT_DIR=$1/.git git log -1 --pretty=format:%ai HEAD`

VERSION_DATE=`echo $DATE | cut -f 1 -d ' ' | tr -d -`
VERSION_TIME=`echo $DATE | cut -f 2 -d ' ' | awk -F: '{printf "%d", $1$2}'`

echo "#define IRSSI_VERSION_DATE $VERSION_DATE"
echo "#define IRSSI_VERSION_TIME $VERSION_TIME"
