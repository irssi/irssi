# /DNS <nick>|<host>|<ip> ...

use Irssi;
use strict;
use Socket;
use POSIX;

use vars qw($VERSION %IRSSI); 
$VERSION = "2.1";
%IRSSI = (
    authors	=> 'Timo Sirainen',
    name	=> 'dns',
    description	=> '/DNS <nick>|<host>|<ip> ...',
    license	=> 'Public Domain',
    changed	=> 'Sun Mar 10 23:23 EET 2002'
);

my (%resolve_hosts, %resolve_nicks, %resolve_print); # resolve queues
my $userhosts; # number of USERHOSTs currently waiting for reply
my $lookup_waiting; # 1 if we're waiting a reply for host lookup

# for the current host lookup
my ($print_server, $print_host, $print_name, @print_ips);
my ($input_skip_next, $input_query);

my $pipe_tag;

sub cmd_dns {
  my ($nicks, $server) = @_;
  return if !$nicks;

  # get list of nicks/hosts we want to know
  my $tag = !$server ? undef : $server->{tag};
  my $ask_nicks = "";
  my $print_error = 0;
  foreach my $nick (split(" ", $nicks)) {
    $nick = lc($nick);
    if ($nick =~ /[\.:]/) {
      # it's an IP or hostname
      $resolve_hosts{$nick} = $tag;
    } else {
      # it's nick
      if (!$print_error && (!$server || !$server->{connected})) {
	$print_error = 1;
	Irssi::print("Not connected to server");
      } else {
	$resolve_nicks{$nick} = 1;
	$ask_nicks .= "$nick ";
      }
    }
  }

  if ($ask_nicks ne "") {
    # send the USERHOST query
    $userhosts++;
    $server->redirect_event('userhost', 1, $ask_nicks, 0, 'redir dns failure', {
                            'event 302' => 'redir dns host',
                            '' => 'event empty' } );
    $server->send_raw("USERHOST :$nicks");
  }

  # ask the IPs/hostnames immediately
  host_lookup() if (!$lookup_waiting);
}

sub sig_failure {
  Irssi::print("Error getting hostname for nick");
  %resolve_nicks = () if (--$userhosts == 0);
}

sub sig_userhost {
  my ($server, $data) = @_;
  $data =~ s/^[^ ]* :?//;
  my @hosts = split(/ +/, $data);

  # move resolve_nicks -> resolve_hosts
  foreach my $host (@hosts) {
    if ($host =~ /^([^=\*]*)\*?=.(.*)@(.*)/) {
      my $nick = lc($1);
      my $user = $2;
      $host = lc($3);

      $resolve_hosts{$host} = $resolve_nicks{$nick};
      delete $resolve_nicks{$nick};
      $resolve_print{$host} = "[$nick!$user"."@"."$host]";
    }
  }

  if (--$userhosts == 0 && %resolve_nicks) {
    # unknown nicks - they didn't contain . or : so it can't be
    # IP or hostname.
    Irssi::print("Unknown nicks: ".join(' ', keys %resolve_nicks));
    %resolve_nicks = ();
  }

  host_lookup() if (!$lookup_waiting);
}

sub host_lookup {
  return if (!%resolve_hosts);

  my ($host) = keys %resolve_hosts;
  $print_server = $resolve_hosts{$host};

  $print_host = undef;
  $print_name = $resolve_print{$host};
  @print_ips = ();

  delete $resolve_hosts{$host};
  delete $resolve_print{$host};

  $input_query = $host;
  $input_skip_next = 0;

  # pipe is used to get the reply from child
  my ($rh, $wh);
  pipe($rh, $wh);

  # non-blocking host lookups with fork()ing
  my $pid = fork();
  if (!defined($pid)) {
    %resolve_hosts = ();
    %resolve_print = ();
    Irssi::print("Can't fork() - aborting");
    close($rh); close($wh);
    return;
  }
  $lookup_waiting++;

  if ($pid > 0) {
    # parent, wait for reply
    close($wh);
    Irssi::pidwait_add($pid);
    $pipe_tag = Irssi::input_add(fileno($rh), INPUT_READ, \&pipe_input, $rh);
    return;
  }

  my $text;
  eval {
    # child, do the lookup
    my $name = "";
    if ($host =~ /^[0-9\.]*$/) {
      # ip -> host
      $name = gethostbyaddr(inet_aton($host), AF_INET);
    } else {
      # host -> ip
      my @addrs = gethostbyname($host);
      if (@addrs) {
	@addrs = map { inet_ntoa($_) } @addrs[4 .. $#addrs];
	$name = join (" ", @addrs);
      }
    }

    $print_name = $input_query if !$print_name;
    if (!$name) {
      $text = "No information for $print_name";
    } else {
      $text = "$print_name: $name";
    }
  };
  $text = $! if (!$text);

  eval {
    # write the reply
    print($wh $text);
    close($wh);
  };
  POSIX::_exit(1);
}

sub pipe_input {
  my $rh = shift;
  my $text = <$rh>;
  close($rh);

  Irssi::input_remove($pipe_tag);
  $pipe_tag = -1;

  my $server = Irssi::server_find_tag($print_server);
  if ($server) {
    $server->print('', $text);
  } else {
    Irssi::print($text);
  }

  $lookup_waiting--;
  host_lookup();
}

Irssi::command_bind('dns', 'cmd_dns');
Irssi::signal_add( {
        'redir dns failure' => \&sig_failure,
        'redir dns host' => \&sig_userhost } );
