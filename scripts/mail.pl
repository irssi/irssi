$VERSION = "2.92";
%IRSSI = (
    authors     => "Timo Sirainen, Matti Hiljanen, Joost Vunderink, Bart Matthaei",
    contact     => "tss\@iki.fi, matti\@hiljanen.com, joost\@carnique.nl, bart\@dreamflow.nl",
    name        => "mail",
    description => "Fully customizable mail counter statusbar item with multiple mailbox and multiple Maildir support",
    license     => "Public Domain",
    url         => "http://irssi.org, http://scripts.irssi.de",
);

# Mail counter statusbar item
# for irssi 0.8.1 by Timo Sirainen
#
# Maildir support added by Matti Hiljanen
# Multiple Maildir/mbox and customization support added by Joost Vunderink
# OLD mailtreatment switch added by Bart Matthaei.
# Improved some regexps in maildirmode by Bart Matthaei.
# Maildirmode regexps (hopefully) fixed for good by Matti Hiljanen. 
#
# You can add any number of mailboxes or Maildirs to watch for new mail in.
# Give them any name and <name>:<count> will appear in your mail
# statusbar item, where <count> is the number of unread messages.
# If only 1 mailbox/Maildir is defined, the statusbar item will have the 
# familiar form [Mail: <count>].
# If you set mail_show_message to ON, irssi will print a message in the
# active window whenever new mail arrives.
#
# Check /mailbox help for help.

use Irssi::TextUI;

my $maildirmode = 0; # maildir=1, file(spools)=0
my $old_is_not_new = 0; 
my $extprog;
my ($last_refresh_time, $refresh_tag);

# for mbox caching
my $last_size, $last_mtime, $last_mailcount, $last_mode;

# list of mailboxes
my %mailboxes = (); 
my %new_mails_in_box = ();
my $nummailboxes = 0; 

# the string to be stored in Irssi's mail_mailboxes setting
my $mailboxsetting = "";

sub cmd_print_help {
  Irssi::print(
  "MAILBOX ADD <num> <file|dir>\n".
  "MAILBOX DEL <num>\n".
  "MAILBOX SHOW\n\n".
  "Statusbar item to keep track of how many (new) emails there are in ".
  "each of your mailboxes/Maildirs.\n\n".
  "/MAILBOX ADD <name> <file|dir>\n".
  "    - Adds a mailbox or a Maildir to the list.\n".
  "/MAILBOX DEL <name>\n".
  "    - Removes mailbox or Maildir named <name> from the list.\n".
  "/MAILBOX SHOW\n".
  "    - Shows a list of the defined mailboxes.\n\n".
  "Use the following commands to change the behaviour:\n\n".
  "/SET MAILDIRMODE on|off\n".
  "    - If maildirmode is on, the mailboxes in the list are assumed to be ".
  "directories. Otherwise they are assumed to be spool files.\n".
  "      Default: off.\n".
  "/SET MAIL_OLDNOTNEW on|off\n".
  "    - If switched on, mail marked als \"OLD\" will not be treated as new.\n".
  "      Default: off.\n".
  "/SET MAIL_EXT_PROGRAM <prog>\n".
  "    - <prog> will be used to check for mail.\n".
  "/SET MAIL_REFRESH_TIME <num>\n".
  "    - Sets the time between checks to <num> seconds.\n      Default: 60.\n".
  "/SET MAIL_SHOW_MESSAGE on|off\n".
  "    - If this is on, a message will be printed in the active window ".
  "whenever new email is received.\n      Default: off.\n".
  "/SET MAIL_SHOW_ONLY_UNREAD on|off\n".
  "    - If you don't want to see a mailbox if it does not contain any new ".
  "mail, set this to on.\n      Default: on.\n" .
  "/SET MAIL_SEPARATOR <char>\n".
  "    - Sets the character to be printed between each mailbox.\n".
  "      The default is a comma.\n".
  "/SET MAIL_FORMAT <format>\n".
  "    - Sets the format of each mailbox.\n".
  "      Allowed variables:\n".
  "      %%n = mailbox name\n".
  "      %%u = number of unread mail\n".
  "      %%r = number of read mail\n".
  "      %%t = total amount of mail\n".
  "      The default format is %%n:%%u/%%t.\n".
  "\nSee also: STATUSBAR"
  ,MSGLEVEL_CRAP);
}

sub mbox_count {
  my $mailfile = shift;
  my $unread = 0;
  my $read = 0;
  my $maildirmode=Irssi::settings_get_bool('maildir_mode');
  my $old_is_not_new=Irssi::settings_get_bool('mail_oldnotnew');

  if ($extprog ne "") {
     $total = `$extprog`;
     chomp $unread;
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

	# count new mails only
	my $internal_removed = 0;
	while (<$f>) {
	  $unread++ if (/^From /);

	  if(!$old_is_not_new) {
	  	$unread-- if (/^Status: R/);
	  } else {
	  	$unread-- if (/^Status: [OR]/);
	  }

	  $read++ if (/^From /);

	  # Remove folder internal data, but only once
	  if (/^Subject: .*FOLDER INTERNAL DATA/) {
	    if ($internal_removed == 0) {
	      $internal_removed = 1;
	      $read--;
	      $unread--;
	    }
	  }
	}
	close($f);
      }
    } else {
      opendir(DIR, "$mailfile/cur") or return 0;
      while (defined(my $file = readdir(DIR))) {
        next if $file =~ /^(.|..)$/;
        # Maildir flags: http://cr.yp.to/proto/maildir.html
        # My old regexps were useless if the MUA added any 
        # non-default flags -qvr
        # 
        # deleted mail
        next if $file =~ /\:.*?T.*?$/;
	    if($old_is_not_new) {
           # when mail gets moved from new to cur it's name _always_
           # changes from uniq to uniq:info, even when it's still not
           # read. I assume "old mail" means mail which hasn't been read
           # yet but it has been "acknowledged" by the user. (it's been
           # moved to cur) -qvr
           if ($file =~ /\:.*?$/) {
              $read++;
      		  next;
           }
        } else {
           if ($file =~ /\:.*?S.*?$/) {
              $read++;
      		  next;
           }
        }
        $unread++;
      }
      closedir(DIR);

      opendir(DIR, "$mailfile/new") or return 0;
      while (defined(my $file = readdir(DIR))) {
        next if $file =~ /^(.|..)$/;
        $unread++;
      }
      closedir(DIR);
    }
  }

  if ($unread eq "" || $unread < 0) {
    $unread = 0;
  }
  if ($read eq "" || $read < 0) {
    $read = 0;
  }

  $last_mailcount = $unread;

  return ($unread, $read);
}

# Checks for mail and sets the statusbar item to the right string.
# Also shows a message in the active window if that setting is set.
sub mail {
  my ($item, $get_size_only) = @_;

  my $result;
  my $format = Irssi::settings_get_str('mail_format');
  my $unread = 0;
  my $read = 0;
  my $total = 0;

  # check all mailboxes for new email
  foreach $name (keys(%mailboxes)) {
    my $box = $mailboxes{$name};
    # replace "~/" at the beginning by the user's home dir
    $box =~ s/^~\//$ENV{'HOME'}\//;

    ($unread, $read) = mbox_count($box);
    $unread = "0" if ($unread eq "");
    $read = "0" if ($read eq "");
    $total = $unread + $read;
    $total = "0" if ($total eq "");

    next if (Irssi::settings_get_bool('mail_show_only_unread') && $unread == 0);

    if ($total eq "") { $total = 0; }
    if (length($result) > 0) {
      $result .= Irssi::settings_get_str('mail_separator');
    }
    my $string = $format;
    $string =~ s/%n/$name/;
    $string =~ s/%u/$unread/;
    $string =~ s/%r/$read/;
    $string =~ s/%t/$total/;
    $result .= $string;
    
    # Show -!- You have <num> new messages in <name>.
    # Show this only if there are any new, unread messages.
    if (Irssi::settings_get_bool('mail_show_message') &&
        $unread > $new_mails_in_box{$name}) {
      $new_mails = $unread - $new_mails_in_box{$name};
      if ($nummailboxes == 1) {
        Irssi::print("You have $new_mails new message" . ($new_mails != 1 ? "s." : "."), MSGLEVEL_CRAP);
      } else {
        Irssi::print("You have $new_mails new message" . ($new_mails != 1 ? "s " : " ") . "in $name.", MSGLEVEL_CRAP);
      }
    }

    $new_mails_in_box{$name} = $unread;
  }
  
  if (length($result) == 0) {
    # no mail - don't print the [Mail: ] at all
    if ($get_size_only) {
      $item->{min_size} = $item->{max_size} = 0;
    }
  } else {
    $item->default_handler($get_size_only, undef, $result, 1);
  }
}

sub refresh_mail {
  Irssi::statusbar_items_redraw('mail');
}

# Adds the mailboxes from a string. Only to be used during startup.
sub add_mailboxes {
  my $boxstring = $_[0];
  my @boxes = split(/,/, $boxstring);

  foreach $dbox(@boxes) {
    my $name = $dbox;
    $name = substr($dbox, 0, index($dbox, '='));
    my $box = $dbox;
    $box = substr($dbox, index($dbox, '=') + 1, length($dbox));
    addmailbox($name, $box);
  }
}

sub addmailbox {
  my ($name, $box) = @_;

  if (exists($mailboxes{$name})) {
    if ($box eq $mailboxes{$name}) {
      Irssi::print("Mailbox $name already set to $box", MSGLEVEL_CRAP);
    } else {
      Irssi::print("Mailbox $name changed to $box", MSGLEVEL_CRAP);
      $new_mails_in_box{$name} = 0;
    }
  } else {
    Irssi::print("Mailbox $name added: " . $box, MSGLEVEL_CRAP);
    $new_mails_in_box{$name} = 0;
    $nummailboxes++;
  }
  $mailboxes{$name} = $box;
}

sub delmailbox {
  my $name = $_[0];

  if (exists($mailboxes{$name})) {
    Irssi::print("Mailbox $name removed", MSGLEVEL_CRAP);
    delete($mailboxes{$name});
    delete($new_mails_in_box{$name});
    $nummailboxes--;
  } else {
    Irssi::print("No such mailbox $name. Use /mailbox show to see a list.", MSGLEVEL_CRAP);
  }
}

sub update_settings_string {
  my $setting;

  foreach $name (keys(%mailboxes)) {
    $setting .= $name . "=" . $mailboxes{$name} . ",";
  }

  Irssi::settings_set_str("mail_mailboxes", $setting);
}

sub cmd_addmailbox {
  my ($name, $box) = split(/ +/, $_[0]);

  if ($name eq "" || $box eq "") {
    Irssi::print("Use /mailbox add <name> <mailbox> to add a mailbox.", MSGLEVEL_CRAP);
    return;
  }

  addmailbox($name, $box);
  update_settings_string();
  refresh_mail();
}

sub cmd_delmailbox {
  my $name = $_[0];

  if ($name eq "") {
    Irssi::print("Use /mailbox del <name> to delete a mailbox.", MSGLEVEL_CRAP);
    return;
  }

  delmailbox($name);
  update_settings_string();
  refresh_mail();
}

sub cmd_showmailboxes {
  if ($nummailboxes == 0) {
    Irssi::print("No mailboxes defined.", MSGLEVEL_CRAP);
    return;
  }
  Irssi::print("Mailboxes:", MSGLEVEL_CRAP);
  foreach $box (keys(%mailboxes)) {
    Irssi::print("$box: " . $mailboxes{$box}, MSGLEVEL_CRAP);
  }
}

sub cmd_mailboxes {
  my ($data, $server, $item) = @_;
  if ($data =~ m/^[(show)|(add)|(del)]/i ) {
    Irssi::command_runsub ('mailbox', $data, $server, $item);
  }
  else {
    Irssi::print("Use /mailbox (show|add|del).")
  }
}

sub init_mailboxes {
  # Add the mailboxes at startup of the script
  my $boxes = Irssi::settings_get_str('mail_mailboxes');
  if (length($boxes) > 0) {
    add_mailboxes($boxes);
  }
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
  refresh_mail;
}


if (!$maildirmode) {
  my $default = "1=" . $ENV{'MAIL'} . ",";
  Irssi::settings_add_str('misc', 'mail_mailboxes', $default);
} else {
  my $default = "1=~/Maildir/,";
  Irssi::settings_add_str('misc', 'mail_mailboxes', $default);
}

Irssi::command_bind('mailbox show', 'cmd_showmailboxes');
Irssi::command_bind('mailbox add', 'cmd_addmailbox');
Irssi::command_bind('mailbox del', 'cmd_delmailbox');
Irssi::command_bind('mailbox help', 'cmd_print_help');
Irssi::command_bind('mailbox', 'cmd_mailboxes');

Irssi::settings_add_str('misc', 'mail_ext_program', '');
Irssi::settings_add_int('misc', 'mail_refresh_time', 60);
Irssi::settings_add_bool('misc', 'maildir_mode', "$maildirmode");
Irssi::settings_add_bool('misc', 'mail_oldnotnew', "$old_is_not_new");
Irssi::settings_add_str('misc', 'mail_separator', ",");
Irssi::settings_add_bool('misc', 'mail_show_message', "0");
Irssi::settings_add_str('misc', 'mail_format', '%n:%u/%t');
Irssi::settings_add_bool('misc', 'mail_show_only_unread', "1");

Irssi::statusbar_item_register('mail', '{sb Mail: $0-}', 'mail');

read_settings();
init_mailboxes();
Irssi::signal_add('setup changed', 'read_settings');
refresh_mail();

# EOF
