use strict;
use warnings;

my $in_code = 1;
my @lines = $ENV{IN_LINES} =~ /(\d+):(\d+)/g;
sub in_lines {
    if (@lines) {
	for (my $i = 0; $i < @lines; $i += 2) {
	    if ($_[0] >= $lines[$i] && $_[0] <= $lines[$i + 1]) {
		return 1;
	    }
	}
	return '';
    } else {
	return 1;
    }
}
while (<>) {
    chomp;
    my $copy;
    my $prot = 0;
    my $code = $in_code;
    if (/^#(define|undef|include|if)/) {
	$copy = 1;
    }
    elsif (/^#[* ]/) {
	$prot = 1;
    }
    elsif (/^[A-Z_]+\s*=/) {
	$prot = 2;
	$in_code = 0;
    }
    elsif (/^((PP)?CODE|PREINIT):/) {
	$prot = 1;
	$in_code = 3;
    }
    elsif (/^[A-Z_]*:/) {
	$prot = 1;
	$in_code = 0;
    }
    elsif (/^[\w:* ]+\s*$/) {
	$in_code = 0;
    }

    if ($prot || (!$copy && !$in_code)) {
	if ($code == 2) {
	    print "}/* -xs- */";
	}
	if ($prot == 2) {
	    print "/* clang-format off */";
	}
	s/^\s+/\t/ if in_lines($.);
	print "/* =xs= $_ */";
	if ($prot == 2) {
	    print "/* clang-format on */";
	}
	if ($in_code == 3) {
	    print "{";
	    $in_code = 2;
	}
	print "\n";
    }
    elsif ($copy) {
	print "$_\n";
    }
    elsif ($in_code) {
	print "$_\n";
    }

}
if ($in_code) {
    print "}/* -xs- */\n";
}
