MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Server

void
autoignore_add(server, nick, level)
	Irssi::Irc::Server server
	char *nick
	int level

int
autoignore_remove(server, mask, level)
	Irssi::Irc::Server server
	char *mask
	int level
