use strict;
use vars qw($VERSION %IRSSI);

use Irssi qw(command signal_add signal_add_first active_win
             settings_get_str settings_get_bool channels windows
	     settings_add_str settings_add_bool get_irssi_dir
	     window_find_refnum signal_stop);
$VERSION = '2.20';
%IRSSI = (
    authors	=> 'Juerd',
    contact	=> 'juerd@juerd.nl',
    name	=> 'Scroll buffer restorer',
    description	=> 'Saves the buffer for /upgrade, so that no information is lost',
    license	=> 'Public Domain',
    url		=> 'http://juerd.nl/irssi/',
    changed	=> 'Thu Sep 22 01:37 CEST 2016',
    changes	=> 'Fixed file permissions (leaked everything via filesystem)',
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

sub _filename { sprintf '%s/scrollbuffer', get_irssi_dir }

sub upgrade {
    my $fn = _filename;
    my $old_umask = umask 0077;
    open my $fh, q{>}, $fn or die "open $fn: $!";
    umask $old_umask;

    print $fh join("\0", map $_->{server}->{address} . $_->{name}, channels), "\n";
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
	printf $fh "%s:%s\n%s", $window->{refnum}, $lines, $buf;
    }
    close $fh;
    unlink sprintf("%s/sessionconfig", get_irssi_dir);
    command 'layout save';
    command 'save';
}

sub restore {
    my $fn = _filename;
    open my $fh, q{<}, $fn or die "open $fn: $!";
    unlink $fn or warn "unlink $fn: $!";

    my @suppress = split /\0/, readline $fh;
    if (settings_get_bool 'upgrade_suppress_join') {
	chomp $suppress[-1];
	@suppress{@suppress} = (2) x @suppress;
    }
    active_win->command('^window scroll off');
    while (my $bla = readline $fh){
	chomp $bla;
	my ($refnum, $lines) = split /:/, $bla;
	next unless $lines;
	my $window = window_find_refnum $refnum;
	unless (defined $window){
	    readline $fh for 1..$lines;
	    next;
	}
	my $view = $window->view;
	$view->remove_all_lines();
	$view->redraw();
	my $buf = '';
	$buf .= readline $fh for 1..$lines;
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
    return unless scalar keys %suppress and settings_get_bool 'upgrade_suppress_join';
    my $key_part = (grep { /^:?[#!+&]/ } split ' ', $second)[0];
    $key_part =~ s/^://;
    my $key = $first->{address} . $key_part;
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

# Remove any left-over file. If 'session' doesn't exist (created by irssi
# during /UPGRADE), neither should our file.
unless (-e sprintf('%s/session', get_irssi_dir)) {
    my $fn = _filename;
    unlink $fn or warn "unlink $fn: $!" if -e $fn;
}
