#!/bin/sh

DATE=`GIT_DIR=$1/.git git log -1 --pretty=format:%ai HEAD`

VERSION_DATE=`echo $DATE | cut -f 1 -d ' ' | tr -d -`
VERSION_TIME=`echo $DATE | cut -f 2 -d ' ' | awk -F: '{printf "%d", $1$2}'`

if test -z "$VERSION_DATE"; then
    exec>&2
    echo "**Error**: `basename "$0"` must be run in a git clone, cannot proceed."
    exit 1
fi

echo "#define IRSSI_VERSION_DATE $VERSION_DATE"
echo "#define IRSSI_VERSION_TIME $VERSION_TIME"

if echo "${VERSION}" | grep -q -- -head; then
  # -head version, get extra details from git if we can
  git_version=$(GIT_DIR=$1/.git git describe --dirty --long --always --tags)
  if [ $? = 0 ]; then
    new_version="$(echo "${VERSION}" | sed 's/-head//')"
    # Because the git tag won't yet include the next release we modify the git
    # describe output using the version defined from configure.ac.
    version="${new_version}-$(echo "${git_version}" | sed 's/^.*-[0-9]\+-//')"
    echo "#undef PACKAGE_VERSION"
    echo "#define PACKAGE_VERSION \"${version}\""
  fi
fi
