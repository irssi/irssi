#!/usr/bin/perl

print "static PERL_SIGNAL_ARGS_REC perl_signal_args[] =\n{\n";

while (<STDIN>) {
	chomp;

	next if (!/^ "([^"]*)"(<.*>)?,\s*(.*)/);
	next if (/\.\.\./);
	next if (/\(/);

	$signal = $1;
	$_ = $3;

	s/char \*[^,]*/string/g;
	s/ulong \*[^,]*/ulongptr/g;
	s/int[^,]*/int/g;
	s/GSList of (\w+)s/gslist_\1/g;

	# core
        s/CHATNET_REC[^,]*/iobject/g;
        s/SERVER_REC[^,]*/iobject/g;
        s/RECONNECT_REC[^,]*/iobject/g;
	s/CHANNEL_REC[^,]*/iobject/g;
	s/QUERY_REC[^,]*/iobject/g;
	s/COMMAND_REC[^,]*/Irssi::Command/g;
	s/NICK_REC[^,]*/Irssi::Nick/g;
	s/LOG_REC[^,]*/Irssi::Log/g;
	s/RAWLOG_REC[^,]*/Irssi::Rawlog/g;
	s/IGNORE_REC[^,]*/Irssi::Ignore/g;
	s/MODULE_REC[^,]*/Irssi::Module/g;

	# irc
	s/BAN_REC[^,]*/Irssi::Ban/g;
	s/NETSPLIT_REC[^,]*/Irssi::Netsplit/g;
	s/NETSPLIT_SERVER_REC[^,]*/Irssi::Netsplitserver/g;

	# irc modules
	s/DCC_REC[^,]*/Irssi::Dcc/g;
	s/AUTOIGNORE_REC[^,]*/Irssi::Autoignore/g;
	s/NOTIFYLIST_REC[^,]*/Irssi::Notifylist/g;

	# fe-common
	s/THEME_REC[^,]*/Irssi::Theme/g;
	s/KEYINFO_REC[^,]*/Irssi::Keyinfo/g;
	s/WINDOW_REC[^,]*/Irssi::Window/g;
	s/WI_ITEM_REC[^,]*/iobject/g;

	s/([\w:]+)(,|$)/"\1"\2/g;
	print "    { -1, \"$signal\", { $_, NULL } },\n";
}

print "\n    { -1, NULL }\n};\n";
