# $Id: mail.pl,v 1.1 2002/03/10 21:33:46 cras Exp $

$VERSION = "2.0";
%IRSSI = (
    authors     => "Matti Hiljanen, Timo Sirainen",
    contact     => "matti\@hiljanen.com, tss\@iki.fi",
    name        => "mail",
    description => "Mail counter statusbar item with maildir support",
    license     => "Public Domain",
    url         => "http://matin.maapallo.org/softa/irssi, http://irssi.org, http://scripts.irssi.de",
);

# Mail counter statusbar item
# for irssi 0.8.1 by Timo Sirainen
#
# Maildir support added by Matti Hiljanen
# 
#  /SET maildir_mode - ON/OFF
#  /SET mail_file - specifies mbox file/Maildir location
#  /SET mail_refresh_time - in seconds, how often to check for new mail
#  /SET mail_ext_program - specify external mail checker program

use Irssi::TextUI;

my $maildirmode = 0; # maildir=1, file(spools)=0
my $extprog;
my ($last_refresh_time, $refresh_tag);

# for mbox caching
my $last_size, $last_mtime, $last_mailcount, $last_mode;

sub mbox_count {
  my $mailfile = shift;
  my $count = 0;
  my $maildirmode=Irssi::settings_get_bool('maildir_mode');
  if ($extprog ne "") {
     $count = `$extprog`;
     chomp $count;
  } else {
     if (!$maildirmode) {
       if (-f $mailfile) {
	 my @stat = stat($mailfile);
	 my $size = $stat[7];
	 my $mtime = $stat[9];

	 # if the file hasn't changed, get the count from cache
	 return $last_mailcount if ($last_size == $size && $last_mtime == $mtime);
	 $last_size = $size;
	 $last_mtime = $mtime;

	 my $f = gensym;
	 return 0 if (!open($f, $mailfile));

	 while (<$f>) {
	    $count++ if (/^From /);
	    $count-- if (/^Subject: .*FOLDER INTERNAL DATA/);
	 }
	 close($f);
	 $last_mailcount = $count;
       }
    } else {
        opendir(DIR, "$mailfile/cur") or return 0;
        while (defined(my $file = readdir(DIR))) {
           next if $file =~ /S/ || $file =~ /^(.|..)$/;
           $count++;
        }
        closedir(DIR);

        opendir(DIR, "$mailfile/new") or return 0;
        while (defined(my $file = readdir(DIR))) {
           next if $file =~ /^(.|..)$/;
           $count++;
        }
        closedir(DIR);
  }
  }
  return $count;
}

sub mail {
  my ($item, $get_size_only) = @_;

  $count = mbox_count(Irssi::settings_get_str('mail_file'));
  if ($count == 0) {
    # no mail - don't print the [Mail: ] at all
    if ($get_size_only) {
      $item->{min_size} = $item->{max_size} = 0;
    }
  } else {
    $item->default_handler($get_size_only, undef, $count, 1);
  }
}

sub refresh_mail {
  Irssi::statusbar_items_redraw('mail');
}

sub read_settings {
  $extprog = Irssi::settings_get_str('mail_ext_program');
  my $time = Irssi::settings_get_int('mail_refresh_time');
  my $mode = Irssi::settings_get_bool('maildir_mode');
  unless ($time == $last_refresh_time) {
     $last_refresh_time = $time;
     Irssi::timeout_remove($refresh_tag) if ($refresh_tag);
     $refresh_tag = Irssi::timeout_add($time*1000, 'refresh_mail', undef);
  }
  return if ($mode == $last_mode);
  $last_mode = $mode;
  if (!$mode) {
     Irssi::settings_set_str('mail_file', "$ENV{'MAIL'}");
  } else {
     Irssi::settings_set_str('mail_file', "$ENV{'HOME'}/Maildir");
  }
  refresh_mail;
}

if (!$maildirmode) {
   Irssi::settings_add_str('misc', 'mail_file', $ENV{'MAIL'});
} else {
   Irssi::settings_add_str('misc', 'mail_file', "$ENV{'HOME'}/Maildir");
}

Irssi::settings_add_str('misc', 'mail_ext_program', '');
Irssi::settings_add_int('misc', 'mail_refresh_time', 60);
Irssi::settings_add_bool('misc', 'maildir_mode', "$maildirmode");

Irssi::statusbar_item_register('mail', '{sb Mail: $0-}', 'mail');

read_settings();
Irssi::signal_add('setup changed', 'read_settings');
refresh_mail();

# EOF
