#!/bin/sh

echo "const char *default_config ="
cat $1|sed 's/\\/\\\\/g'|sed 's/"/\\"/g'|sed 's/^/\"/'|sed 's/$/\\n\"/'
echo ";"
