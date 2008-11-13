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

@files = `find src -name '*.c'`;

foreach $file (@files) {
   open (FILE, "$file");
   while (<FILE>) {
      chomp;
      if (m!/\*.SYNTAX\:! || $state) {
	 s/^\s+/ /;
	 s/.*SYNTAX: //;
	 if (/^ [A-Z]+/) {
	    push @lines, $line;
	    $line = "";
	    s/^ //;
	 }
	 $line .= $_;
	 if (m!\*/!) {
	    $line =~ s!\*/!!;
	    push @lines, $line;
	    $line = "";
	    $state = 0;
	 } else {
	    $state = 1;
	 }
      }
   }
   close (FILE);
}
while (<docs/help/in/*.in>) {
   next if (/Makefile/);

   open (FILE, "$_");
   @data = <FILE>;
   close (FILE);
   $count = 0;
   foreach $DATARIVI (@data) {
      if ($DATARIVI =~ /\@SYNTAX\:(.+)\@/) {
          $SYNTAX = join "\n", (grep /^\U$1 /, @lines);
	  $SYNTAX .= "\n" if $SYNTAX;
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
