#include "../core/module.h"

#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-queries.h"

#include "bans.h"
#include "modes.h"
#include "mode-lists.h"
#include "netsplit.h"
#include "ignore.h"

#include "dcc/dcc.h"
#include "flood/autoignore.h"
#include "notifylist/notifylist.h"

typedef IRC_SERVER_REC *Irssi__Irc__Server;
typedef IRC_SERVER_CONNECT_REC *Irssi__Irc__Connect;
typedef IRC_CHANNEL_REC *Irssi__Irc__Channel;
typedef QUERY_REC *Irssi__Irc__Query;

typedef BAN_REC *Irssi__Irc__Ban;
typedef DCC_REC *Irssi__Irc__Dcc;
typedef NETSPLIT_REC *Irssi__Irc__Netsplit;
typedef NETSPLIT_SERVER_REC *Irssi__Irc__Netsplitserver;
typedef AUTOIGNORE_REC *Irssi__Irc__Autoignore;
typedef NOTIFYLIST_REC *Irssi__Irc__Notifylist;
typedef IGNORE_REC *Irssi__Irc__Ignore;
