# NOTE: this is printed through printf()-like function,
# so no extra percent characters.

# %%s can be used once, it contains the
# use Irssi; use Irssi::Irc; etc..
package Irssi::Core;

use Symbol qw(delete_package);

sub destroy {
  my $package = "Irssi::Script::".$_[0];
  delete_package($package);
}

sub eval_data {
  my ($data, $id) = @_;
  destroy($id);

  my $package = "Irssi::Script::$id";
  my $eval = qq{package $package; %s sub handler { $data; }};
  {
      # hide our variables within this block
      my ($filename, $package, $data);
      eval $eval;
  }
  die $@ if $@;

  eval {$package->handler;};
  die $@ if $@;
}

sub eval_file {
  my ($filename, $id) = @_;

  local *FH;
  open FH, $filename or die "File not found: $filename";
  local($/) = undef;
  my $data = <FH>;
  close FH;
  $/ = '\n';

  eval_data($data, $id);
}
