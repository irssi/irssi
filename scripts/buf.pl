use strict;
use vars qw($VERSION %IRSSI);

use Irssi qw(command signal_add signal_add_first active_win
             settings_get_str settings_get_bool channels windows
	     settings_add_str settings_add_bool get_irssi_dir
	     window_find_refnum signal_stop);
$VERSION = '2.13';
%IRSSI = (
    authors	=> 'Juerd',
    contact	=> 'juerd@juerd.nl',
    name	=> 'Scroll buffer restorer',
    description	=> 'Saves the buffer for /upgrade, so that no information is lost',
    license	=> 'Public Domain',
    url		=> 'http://juerd.nl/irssi/',
    changed	=> 'Mon May 13 19:41 CET 2002',
    changes	=> 'Severe formatting bug removed * oops, I ' .
                   'exposed Irssi to ircII foolishness * sorry ' .
		   '** removed logging stuff (this is a fix)',
    note1	=> 'This script HAS TO BE in your scripts/autorun!',
    note2	=> 'Perl support must be static or in startup',
);

# Q: How can I get a very smooth and clean upgrade?
#
# A: /set -clear upgrade_separator
#    /set upgrade_suppress_join ON (default)
#    /set channel_sync OFF

# Q: Can I use color in the upgrade_separator?
# Q: Is it possible to save my command history?
# Q: Can I prevent the screen from blinking?
# Q: Can you make it faster?
#
# A: Probably not, but if you can do it, tell me how.

use Irssi::TextUI;
use Data::Dumper;

my %suppress;

sub upgrade {
    open BUF, sprintf('>%s/scrollbuffer', get_irssi_dir) or die $!;
    print BUF join("\0", map $_->{server}->{address} . $_->{name}, channels), "\n";
    for my $window (windows) {
	next unless defined $window;
	next if $window->{name} eq 'status';
	my $view = $window->view;
	my $line = $view->get_lines;
	my $lines  = 0;
	my $buf = '';
	if (defined $line){
	    {
		$buf .= $line->get_text(1) . "\n";
		$line = $line->next;
		$lines++;
		redo if defined $line;
	    }
	}
	printf BUF "%s:%s\n%s", $window->{refnum}, $lines, $buf;
    }
    close BUF;
    unlink sprintf("%s/sessionconfig", get_irssi_dir);
    command 'layout save';
    command 'save';
}

sub restore {
    open BUF, sprintf('<%s/scrollbuffer', get_irssi_dir) or die $!;
    my @suppress = split /\0/, <BUF>;
    if (settings_get_bool 'upgrade_suppress_join') {
	chomp $suppress[-1];
	@suppress{@suppress} = (2) x @suppress;
    }
    active_win->command('^window scroll off');
    while (my $bla = <BUF>){
	chomp $bla;
	my ($refnum, $lines) = split /:/, $bla;
	next unless $lines;
	my $window = window_find_refnum $refnum;
	unless (defined $window){
	    <BUF> for 1..$lines;
	    next;
	}
	my $view = $window->view;
	$view->remove_all_lines();
	$view->redraw();
	my $buf = '';
	$buf .= <BUF> for 1..$lines;
	my $sep = settings_get_str 'upgrade_separator';
	$sep .= "\n" if $sep ne '';
	$window->gui_printtext_after(undef, MSGLEVEL_CLIENTNOTICE, "$buf\cO$sep");
	$view->redraw();
    }
    active_win->command('^window scroll on');
    active_win->command('^scrollback end');
}

sub suppress {
    my ($first, $second) = @_;
    return
	unless scalar keys %suppress
	and settings_get_bool 'upgrade_suppress_join';
    my $key = $first->{address} . 
	(grep { (s/^://, /^[#!+&]/) } split ' ', $second)[0];
    if (exists $suppress{$key} and $suppress{$key}--) {
	signal_stop();
	delete $suppress{$key} unless $suppress{$key};
    }
}

settings_add_str  'buffer', 'upgrade_separator'     => '=Upgrade=';
settings_add_bool 'buffer', 'upgrade_suppress_join' => 1;

signal_add_first 'session save'    => 'upgrade';
signal_add_first 'session restore' => 'restore';
signal_add       'event 366'       => 'suppress';
signal_add       'event join'      => 'suppress';

unless (-f sprintf('%s/scripts/autorun/buf.pl', get_irssi_dir)) {
    Irssi::print('PUT THIS SCRIPT IN ~/.irssi/scripts/autorun/ BEFORE /UPGRADING!!');
}
