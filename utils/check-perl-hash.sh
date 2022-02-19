#!/bin/sh
# make sure perl hashes have correct length
find src/perl \( -name '*.c' -o -name '*.xs' \) -exec grep -n hv_store {} + | perl -l -ne 'if (/"(\w+)",\s*(\d+)/ && $2 != length $1) { $X=1; print "Incorrect key length in $_" } END { exit $X }'
