#!/usr/bin/perl
#
# This script reads the syntaces of commands from irssi source tree.
# Then it browses through all '.in' files in the current directory and
# substitutes '@SYNTAX:foo@' tags with real syntaces found. This data
# is written into the corresponding files without the '.in' extension.
# For example:  help.in -> ../help
#
# This path has to be changed. It should point to your irssi/src directory
# Remember to include the asterisk ('*').
$SRC_PATH='src';

$FOO = `find src -name '*.c' -exec perl findsyntax.pl \{\} \\; | sed 's/.*SYNTAX: //' > irssi_syntax`;

while (<docs/help/in/*.in>) {
   next if (/Makefile/);

   open (FILE, "$_");
   @data = <FILE>;
   close (FILE);
   $count = 0;
   foreach $DATARIVI (@data) {
      if ($DATARIVI =~ /\@SYNTAX\:(.+)\@/) {
          $etsittava = "\U$1 ";
          $SYNTAX = `grep \'^$etsittava\' irssi_syntax`;
	  $SYNTAX =~ s/\*\///g;
	  $SYNTAX =~ s/ *$//; $SYNTAX =~ s/ *\n/\n/g;

	  # add %| after "COMMAND SUB " so parameters will indent correctly
	  $SYNTAX =~ s/^([A-Z ]+)/\1%|/;
	  $SYNTAX =~ s/(\n[A-Z ]+)/\1%|/g;
	  # no need for this if there's no parameters
	  $SYNTAX =~ s/%\|$//;
          $DATARIVI = $SYNTAX;
      } elsif ($DATARIVI =~ /^\S+/) {
	if ($data[$count+1] =~ /^\S+/) {
	  chomp $DATARIVI;
	  $DATARIVI =~ s/ *$//g;
	  $DATARIVI .= " ";
	}
      } else {
	  $DATARIVI =~ s/^\t/         / while ($DATARIVI =~ /^\t/);
      }
      $count++;
   }

   # must always end with empty line
   push @data, "\n" if ($data[@data-1] ne "\n");
   push @data, "\n" if ($data[@data-2] !~ /\n$/);

   $newfilename = $_; $newfilename =~ s/\.in$//;
   $newfilename =~ s/\/in\//\//;
   open (NEWFILE, ">$newfilename");
   print NEWFILE @data;
   close (NEWFILE);
}
unlink "irssi_syntax";
