# NOTE: this is printed through printf()-like function,
# so no extra percent characters.

# %%d : must be first - 1 if perl libraries are to be linked 
#       statically with irssi binary, 0 if not
# %%s : must be second - use Irssi; use Irssi::Irc; etc..
package Irssi::Core;

use Symbol;

sub is_static {
  return %d;
}

sub destroy {
  eval { $_[0]->UNLOAD() if $_[0]->can('UNLOAD'); };
  Symbol::delete_package($_[0]);
}

sub eval_data {
  my ($data, $id) = @_;
  destroy("Irssi::Script::$id");

  my $package = "Irssi::Script::$id";
  my $eval = qq{package $package; %s sub handler { $data; }};
  {
      # hide our variables within this block
      my ($filename, $package, $data);
      eval $eval;
  }
  die $@ if $@;

  my $ret;
  eval { $ret = $package->handler; };
  die $@ if $@;
  return $ret;
}

sub eval_file {
  my ($filename, $id) = @_;

  local *FH;
  open FH, $filename or die "File not found: $filename";
  local($/) = undef;
  my $data = <FH>;
  close FH;
  local($/) = "\n";

  eval_data($data, $id);
}
