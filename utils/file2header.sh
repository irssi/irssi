#!/bin/sh

echo "const char *$2 ="
sed 's/\\/\\\\/g;s/"/\\"/g;s/^/\"/;s/$/\\n\"/' "$1"
echo ";"
