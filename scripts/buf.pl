# Highly experimental. use it at your own risk.

use strict;
use vars qw($VERSION %IRSSI);

use Irssi 20020120; # 21/01/2002, 18:00 cvs commit
# at http://juerd.nl/irssi/temporary.deb for debian sid
$VERSION = "2.06";
%IRSSI = (
    authors	=> "Juerd",
    contact	=> "juerd\@juerd.nl",
    name	=> "Scroll buffer thingy",
    description	=> "Saves the buffer for /upgrade",
    license	=> "Public Domain",
    url		=> "http://juerd.nl/irssi/",
    changed	=> "Tue Feb 28 16:22 CET 2002",
    changes	=> "+logging workaround (untested, suggested by darix)"
);

# Saves the Irssi scrollbuffer and displays it after /UPGADEing.
# Additionaly saves your settings and layout.
# HAS TO BE in $irssidir/scripts/autorun (don't forget to load the
# perl module if you have to... put /load perl in $irssidir/startup)

# Q: How can I get a very smooth and clean upgrade?
# A: /set -clear upgrade_separator
#    /set upgrade_suppress_join ON (default)
#    /set channel_sync OFF

# Q: Can I use color in the upgrade_separator?
# Q: Is it possible to save my command history?
# Q: Can I prevent the screen from blinking?
# Q: Can you make it faster?
# A: Probably not, but if you can do it, tell me how.

use Irssi::TextUI;
use Data::Dumper;

my %suppress;

sub upgrade {
    open (BUF, sprintf('>%s/scrollbuffer', Irssi::get_irssi_dir()));
    my $logging = Irssi::settings_get_bool('autolog') || 0;
    print BUF join("\0", map $_->{server}->{address} . $_->{name}, Irssi::channels()), "\n";
    print BUF "$logging\n";
    for my $window (Irssi::windows()){
	next unless defined $window;
	next if $window->{name} eq 'status';
	my $view = $window->view();
	my $line = $view->get_lines();
	my $lines  = 0;
	my $buf = '';
	if (defined $line){
	    {
		$buf .= $line->get_text(1) . "\n";
		$line = $line->next();
		$lines++;
		redo if defined $line;
	    }
	}
	printf BUF ("%s:%s\n%s", $window->{refnum}, $lines, $buf);
    }
    close BUF;
    unlink sprintf("%s/sessionconfig", Irssi::get_irssi_dir());
    Irssi::command('/layout save');
    Irssi::command('/set autolog off') if $logging;
    Irssi::command('/save');
}

sub restore {
    open (BUF, sprintf('<%s/scrollbuffer', Irssi::get_irssi_dir()));
    my @suppress = split /\0/, <BUF>;
    my $logging = <BUF>;
    chomp $logging;
    if (Irssi::settings_get_bool('upgrade_suppress_join')) {
	chomp $suppress[-1];
	@suppress{@suppress} = (2) x @suppress;
    }
    Irssi::active_win()->command('/^window scroll off');
    while (my $bla = <BUF>){
	chomp $bla;
	my ($refnum, $lines) = split /:/, $bla;
	next unless $lines;
	my $window = Irssi::window_find_refnum($refnum);
	unless (defined $window){
	    <BUF> for 1..$lines;
	    Irssi::print("no $refnum?");
	    next;
	}
	my $view = $window->view();
	$view->remove_all_lines();
	$view->redraw();
	my $buf = '';
	$buf .= <BUF> for 1..$lines;
	my $sep = Irssi::settings_get_str('upgrade_separator');
	$sep .= "\n" if $sep ne '';
	$window->gui_printtext_after(undef, MSGLEVEL_CLIENTNOTICE, "$buf\cO$sep");
	$view->redraw();
    }
    Irssi::active_win()->command('/^window scroll on');
    Irssi::active_win()->command('/^scrollback end');
    Irssi::command('/set autolog on') if $logging;
}

sub suppress {
    my ($first, $second) = @_;
    return unless scalar keys %suppress
	and Irssi::settings_get_bool('upgrade_suppress_join');
    my $key = $first->{address} . 
	      (grep { (s/^://, /^[#!+&]/) } split ' ', $second)[0];
    if (exists $suppress{$key} and $suppress{$key}--) {
	Irssi::signal_stop();
	delete $suppress{$key} unless $suppress{$key};
    }
}

# Don't use these :P they're for testing
#Irssi::command_bind('emulate_upgrade', 'upgrade');
#Irssi::command_bind('emulate_restore', 'restore');

Irssi::settings_add_str('buffer', 'upgrade_separator', '=Upgrade=');
Irssi::settings_add_bool('buffer', 'upgrade_suppress_join', 1);

Irssi::signal_add_first('session save', 'upgrade');
Irssi::signal_add_first('session restore', 'restore');
Irssi::signal_add('event 366', 'suppress');
Irssi::signal_add('event join', 'suppress');

unless (-f sprintf('%s/scripts/autorun/buf.pl', Irssi::get_irssi_dir())) {
    Irssi::print('PUT THIS SCRIPT IN ~/.irssi/scripts/autorun/ BEFORE /UPGRADING!!');
    Irssi::print('And don\'t forget to /load perl using ~/.irssi/autostart');
}
