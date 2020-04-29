use strict;
use warnings;

my @diff = <>;
if (@diff && $diff[0] !~ /^---/) {
    die "Not valid diff output";
}
my @offs = $ENV{OFFSETS} =~ /(\d+):(\d+)/g;
sub in_off {
    if (@offs) {
	for (my $i = 0; $i < @offs; $i += 2) {
	    if ($_[0] + $_[1] >= $offs[$i] && $_[0] <= $offs[$i] + $offs[$i + 1]) {
		return 1;
	    }
	}
	return '';
    } else {
	return 1;
    }
}

print "<?xml version='1.0'?>
<replacements xml:space='preserve' incomplete_format='false'>\n";
my $open;
for (@diff) {
    if (/^\@\@ -(\d+)(,(\d+))? /) {
	if ($open) {
	    print "</replacement>\n";
	}
	if (in_off($1-($3//1?1:0), $3//1)) {
	    print "<replacement offset='@{[$1-($3//1?1:0)]}' length='@{[$3//1]}'>";
	    $open = 1;
	} else {
	    $open = 0;
	}
    }
    elsif (/^[+] +(\d+)/ && $open) {
	print "&#$1;";
    }
}
if ($open) {
    print "</replacement>\n";
}
print "</replacements>\n";
