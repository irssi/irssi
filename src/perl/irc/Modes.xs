MODULE = Irssi::Irc	PACKAGE = Irssi::Irc

char *
modes_join(old, mode, channel)
	char *old
	char *mode
        int channel

#*******************************
MODULE = Irssi::Irc	PACKAGE = Irssi::Irc::Channel  PREFIX = channel_
#*******************************

char *
ban_get_mask(channel, nick)
	Irssi::Irc::Channel channel
	char *nick

Irssi::Irc::Ban
banlist_add(channel, ban, nick, time)
	Irssi::Irc::Channel channel
	char *ban
	char *nick
	time_t time

void
banlist_remove(channel, ban)
	Irssi::Irc::Channel channel
	char *ban

Irssi::Irc::Ban
banlist_exception_add(channel, ban, nick, time)
	Irssi::Irc::Channel channel
	char *ban
	char *nick
	time_t time

void
banlist_exception_remove(channel, ban)
	Irssi::Irc::Channel channel
	char *ban

void
invitelist_add(channel, mask)
	Irssi::Irc::Channel channel
	char *mask

void
invitelist_remove(channel, mask)
	Irssi::Irc::Channel channel
	char *mask
