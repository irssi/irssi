#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#undef _
#include "common.h"
#include "network.h"
#include "commands.h"
#include "server.h"
#include "log.h"
#include "rawlog.h"
#include "settings.h"

#include "irc/core/bans.h"
#include "irc/core/channels.h"
#include "irc/core/query.h"
#include "irc/core/irc.h"
#include "irc/core/irc-server.h"
#include "irc/core/server-reconnect.h"
#include "irc/core/server-setup.h"
#include "irc/core/nicklist.h"
#include "irc/core/masks.h"
#include "irc/core/modes.h"
#include "irc/core/mode-lists.h"
#include "irc/core/netsplit.h"
#include "irc/core/ignore.h"

#include "irc/dcc/dcc.h"
#include "irc/flood/autoignore.h"
#include "irc/notifylist/notifylist.h"

#include "fe-common/core/windows.h"

#define new_pv(a) (newSVpv((a) == NULL ? "" : (a), (a) == NULL ? 0 : strlen(a)))

typedef COMMAND_REC *Irssi__Command;
typedef LOG_REC *Irssi__Log;
typedef RAWLOG_REC *Irssi__Rawlog;

typedef CHANNEL_REC *Irssi__Channel;
typedef QUERY_REC *Irssi__Query;
typedef IRC_SERVER_REC *Irssi__Server;
typedef IRC_SERVER_CONNECT_REC *Irssi__Connect;
typedef RECONNECT_REC *Irssi__Reconnect;
typedef NICK_REC *Irssi__Nick;
typedef BAN_REC *Irssi__Ban;
typedef NETSPLIT_REC *Irssi__Netsplit;
typedef NETSPLIT_SERVER_REC *Irssi__Netsplitserver;
typedef IGNORE_REC *Irssi__Ignore;

typedef DCC_REC *Irssi__Dcc;
typedef AUTOIGNORE_REC *Irssi__Autoignore;
typedef NOTIFYLIST_REC *Irssi__Notifylist;

typedef WINDOW_REC *Irssi__Window;
typedef WI_ITEM_REC *Irssi__Windowitem;
