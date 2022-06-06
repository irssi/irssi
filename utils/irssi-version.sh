#!/bin/sh

DATE=`grep '^v' $1/NEWS | head -1`
VERSION_DATE=`echo "$DATE" | cut -f 2 -d ' ' | tr -d -`
case $VERSION_DATE in
  *xx)
    VERSION_DATE=`date +%Y%m%d`
    ;;
esac
VERSION_TIME=`echo "$DATE" | cut -f 1 -d ' ' | tr -d v | tr .- ' '`
VERSION_TIME=`printf %d%d%02d $VERSION_TIME 2>/dev/null | cut -c 1-4`

if echo "${VERSION}" | grep -q -- -head; then
  # -head version, get extra details from git if we can
  DATE=`GIT_DIR=$1/.git git log -1 --pretty=format:%ci HEAD 2>/dev/null`

  VERSION_DATE=`echo $DATE | cut -f 1 -d ' ' | tr -d -`

  if test -z "$VERSION_DATE"; then
    VERSION_DATE=`date +%Y%m%d`
  fi

  git_version=$(GIT_DIR=$1/.git git describe --dirty --long --tags --match '[0-9]*.[0-9]*' 2>/dev/null)
  if [ $? = 0 ]; then
    echo "#undef PACKAGE_VERSION"
    echo "#define PACKAGE_VERSION \"${git_version}\""
  fi
fi

echo "#define IRSSI_VERSION_DATE $VERSION_DATE"
echo "#define IRSSI_VERSION_TIME $VERSION_TIME"
