#!/bin/sh

echo "const char *$2 ="
cat $1|sed 's/\\/\\\\/g'|sed 's/"/\\"/g'|sed 's/^/\"/'|sed 's/$/\\n\"/'
echo ";"
