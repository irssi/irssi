#!/usr/bin/perl

print "static PERL_SIGNAL_ARGS_REC perl_signal_args[] =\n{\n";

while (<STDIN>) {
	chomp;

	last if (/UI common/);
	next if (!/^ "([^"]*)"(<.*>)?,\s*(.*)/);
	next if (/\.\.\./);
	next if (/\(/);

	$signal = $1;
	$_ = $3;

	s/char \*[^,]*/string/g;
	s/ulong \*[^,]*/ulongptr/g;
	s/int[^,]*/int/g;
	s/GSList of (\w+)s/gslist_\1/g;

        s/SERVER_REC \*[^,]*/Irssi::Server/g;
        s/RECONNECT_REC \*[^,]*/Irssi::Reconnect/g;
	s/CHANNEL_REC \*[^,]*/Irssi::Channel/g;
	s/COMMAND_REC \*[^,]*/Irssi::Command/g;
	s/NICK_REC \*[^,]*/Irssi::Nick/g;
	s/BAN_REC \*[^,]*/Irssi::Ban/g;
	s/NETSPLIT_REC \*[^,]*/Irssi::Netsplit/g;
	s/DCC_REC \*[^,]*/Irssi::Dcc/g;
	s/LOG_REC \*[^,]*/Irssi::Log/g;
	s/LOG_ITEM_REC \*[^,]*/Irssi::Logitem/g;
	s/PLUGIN_REC \*[^,]*/Irssi::Plugin/g;
	s/AUTOIGNORE_REC \*[^,]*/Irssi::Autoignore/g;

	s/([\w:]+)(,|$)/"\1"\2/g;
	print "    { -1, \"$signal\", { $_, NULL } },\n";
}

print "\n    { -1, NULL }\n};\n";
