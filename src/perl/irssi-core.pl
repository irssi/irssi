# NOTE: this is printed through printf()-like function,
# so no extra percent characters.

# %%d : must be first - 1 if perl libraries are to be linked 
#       statically with irssi binary, 0 if not
# %%s : must be second - use Irssi; use Irssi::Irc; etc..
package Irssi::Core;

use Symbol;

$SIG{__WARN__} = sub {
  my @msg = @_;
  s/%%/%%%%/g for @msg;
  print @msg;
};

sub is_static {
  return %d;
}

sub destroy {
  eval { $_[0]->UNLOAD() if $_[0]->can('UNLOAD'); };
  Symbol::delete_package($_[0]);
}

sub eval_data {
  my $ret = eval do {
    my ($data, $id) = @_;
    destroy("Irssi::Script::$id");
    my $code = qq{package Irssi::Script::$id; %s $data};
    $code
  };
  $@ and die $@;
  $ret
}

sub eval_file {
  my ($filename, $id) = @_;

  open my $fh, '<', $filename or die "Can't open $filename: $!";
  my $data = do {local $/; <$fh>};
  close $fh;

  $filename =~ s/(["\\])/\\$1/g;
  $filename =~ s/\n/\\n/g;

  $data = qq{\n#line 1 "$filename"\n$data};

  eval_data($data, $id);
}
