push @ExtUtils::MakeMaker::Overridable, qw(pm_to_blib);
my $verb = $AM_DEFAULT_VERBOSITY;
{ package MY;
    sub _center {
	my $z = shift;
	(length $z == 2 ? "  $z   " : length $z == 4 ? " $z  " : " $z ").'   '
    }
    sub _silent_cmd {
	my $z = shift;
	$z =~ s{\t(?:- ?)?\K(?=\$\((?|(CC)CMD|(XS)UBPPRUN|(LD|MV|CHMOD)|(RM)_R?F|(CP)_NONEMPTY|FULL_(AR)\)))}{\$(PL_AM_V_$1)}g;
	$z
    }
    sub c_o { _silent_cmd(shift->SUPER::c_o(@_)) }
    sub xs_c { _silent_cmd(shift->SUPER::xs_c(@_)) }
    sub xs_o { _silent_cmd(shift->SUPER::xs_o(@_)) }
    sub dynamic_lib { _silent_cmd(shift->SUPER::dynamic_lib(@_)) }
    sub static_lib { _silent_cmd(shift->SUPER::static_lib(@_)) }
    sub dynamic_bs {
	my $ret = shift->SUPER::dynamic_bs(@_);
	$ret =~ s{Running Mkbootstrap for}{\$(PL_AM_V_BS_Text)}g;
	_silent_cmd($ret)
    }
    sub pm_to_blib {
	my $ret = shift->SUPER::pm_to_blib(@_);
	$ret =~ s{^(\t(?:- ?)?)(?:\$\(NOECHO\) ?)?(.*-e ['"]pm_to_blib(.*\\\n)*.*)$}{$1\$(PL_AM_V_BLIB)$2\$(PL_AM_V_BLIB_Hide)}mg;
	$ret
    }
    sub post_constants {
	my $ret = shift->SUPER::post_constants(@_);
	my @terse = qw(cc xs ld chmod cp ar blib);
	my @silent = qw(mv rm);
	my @special = qw(BLIB_Hide);

	#default verbosity from command line parameter
	$ret .= "
AM_DEFAULT_VERBOSITY = @{[$verb ? 1 : 0]}
";
	#default options forward
	$ret .= "
PL_AM_V_${_} = \$(pl_am__v_${_}_\$(V))
pl_am__v_${_}_ = \$(pl_am__v_${_}_\$(AM_DEFAULT_VERBOSITY))
" for @special, map uc, @terse, @silent;

	#quoted plain text needs extra quotes
	$ret .= "
PL_AM_V_BS_Text = \"\$(pl_am__v_BS_Text_\$(V))\"
pl_am__v_BS_Text_ = \$(pl_am__v_BS_Text_\$(AM_DEFAULT_VERBOSITY))
"
	#hide pm_to_blib output
. "
pl_am__v_BLIB_Hide_0 = \$(DEV_NULL)
pl_am__v_BLIB_Hide_1 = 
"
	#text for Mkbootstrap
. "
pl_am__v_BS_Text_0 = \"@{[_center('BS')]}\"
pl_am__v_BS_Text_1 = \"Running Mkbootstrap for\"
";
	#"terse" output
	$ret .= "
pl_am__v_${_}_0 = \$(NOECHO)echo \"@{[_center($_)]}\" \$\@;
" for map uc, @terse;

	#no output
	$ret .= "
pl_am__v_${_}_0 = \$(NOECHO)
" for map uc, @silent;

	#in verbose mode the "terse" echo expands to nothing
	$ret .= "
pl_am__v_${_}_1 = 
" for map uc, @terse, @silent;
	$ret
    }
}
1;
