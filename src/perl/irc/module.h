#include "../common/module.h"

#include "irc.h"
#include "irc-servers.h"
#include "irc-channels.h"
#include "irc-queries.h"
#include "irc-nicklist.h"
#include "irc-masks.h"

#include "bans.h"
#include "modes.h"
#include "mode-lists.h"
#include "netsplit.h"
#include "servers-redirect.h"

#include "dcc/dcc.h"
#include "dcc/dcc-file.h"
#include "dcc/dcc-chat.h"
#include "dcc/dcc-get.h"
#include "dcc/dcc-send.h"
#include "notifylist/notifylist.h"

#include "proxy/proxy.h"

typedef IRC_SERVER_REC *Irssi__Irc__Server;
typedef IRC_SERVER_CONNECT_REC *Irssi__Irc__Connect;
typedef IRC_CHANNEL_REC *Irssi__Irc__Channel;
typedef QUERY_REC *Irssi__Irc__Query;
typedef NICK_REC *Irssi__Irc__Nick;

typedef BAN_REC *Irssi__Irc__Ban;
typedef DCC_REC *Irssi__Irc__Dcc;
typedef CHAT_DCC_REC *Irssi__Irc__Dcc__Chat;
typedef GET_DCC_REC *Irssi__Irc__Dcc__Get;
typedef SEND_DCC_REC *Irssi__Irc__Dcc__Send;
typedef NETSPLIT_REC *Irssi__Irc__Netsplit;
typedef NETSPLIT_SERVER_REC *Irssi__Irc__Netsplitserver;
typedef NETSPLIT_CHAN_REC *Irssi__Irc__Netsplitchannel;
typedef NOTIFYLIST_REC *Irssi__Irc__Notifylist;

typedef CLIENT_REC *Irssi__Irc__Client;
