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

$FOO = `find src -name '*.c' -exec ./findsyntax.pl \{\} \\; | sed 's/.*SYNTAX: //' > irssi_syntax`;


while (<docs/help/in/*.in>) {
   open (FILE, "$_");
   @data = <FILE>;
   close (FILE);
   foreach $DATARIVI (@data) {
      if ($DATARIVI =~ /\@SYNTAX\:(.+)\@/) {
          $etsittava = "\U$1 ";
          $SYNTAX = `grep \'^$etsittava\' irssi_syntax`;
	  $SYNTAX =~ s/\*\///g;
	  $SYNTAX =~ s/ *$//; $SYNTAX =~ s/ *\n/\n/g;
          $DATARIVI = $SYNTAX;
      }
   }
   $newfilename = $_; $newfilename =~ s/\.in$//;
   $newfilename =~ s/\/in\//\//;
   open (NEWFILE, ">$newfilename");
   print NEWFILE @data;
   close (NEWFILE);
}
unlink "irssi_syntax";
