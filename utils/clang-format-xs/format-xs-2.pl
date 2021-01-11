use strict;
use warnings;

my $doc = do { local $/; <> };

$doc =~ s{\}[ \t]*/[*] -xs- [*]/\s*}{}g;
$doc =~ s{^[ \t]*?/[*] =xs= (.*?) [*]/(\s*\{$)?}{$1}gms;
$doc =~ s{^[ \t]*?/[*] clang-format off [*]//[*] =xs= (.*?) [*]/\s?/[*] clang-format on [*]/(\s*\{$)?}{$1}gms;

print $doc;
