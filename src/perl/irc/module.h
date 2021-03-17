#include <irssi/src/perl/common/module.h>

#include <irssi/src/irc/core/irc.h>
#include <irssi/src/irc/core/irc-chatnets.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/irc-queries.h>
#include <irssi/src/irc/core/irc-nicklist.h>
#include <irssi/src/irc/core/irc-masks.h>
#include <irssi/src/irc/core/irc-cap.h>

#include <irssi/src/irc/core/bans.h>
#include <irssi/src/irc/core/modes.h>
#include <irssi/src/irc/core/mode-lists.h>
#include <irssi/src/irc/core/netsplit.h>
#include <irssi/src/irc/core/servers-redirect.h>

#include <irssi/src/irc/dcc/dcc.h>
#include <irssi/src/irc/dcc/dcc-file.h>
#include <irssi/src/irc/dcc/dcc-chat.h>
#include <irssi/src/irc/dcc/dcc-get.h>
#include <irssi/src/irc/dcc/dcc-send.h>
#include <irssi/src/irc/notifylist/notifylist.h>

#include <irssi/src/irc/proxy/proxy.h>

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
