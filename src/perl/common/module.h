#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#undef _
#include "common.h"
#include "network.h"
#include "commands.h"
#include "log.h"
#include "rawlog.h"
#include "ignore.h"
#include "settings.h"
#include "masks.h"

#include "servers.h"
#include "servers-reconnect.h"
#include "servers-setup.h"
#include "channels.h"
#include "queries.h"
#include "nicklist.h"

#include "perl/perl-common.h"

#include "fe-common/core/windows.h"

typedef COMMAND_REC *Irssi__Command;
typedef LOG_REC *Irssi__Log;
typedef LOG_ITEM_REC *Irssi__LogItem;
typedef RAWLOG_REC *Irssi__Rawlog;
typedef IGNORE_REC *Irssi__Ignore;

typedef SERVER_REC *Irssi__Server;
typedef SERVER_CONNECT_REC *Irssi__Connect;
typedef RECONNECT_REC *Irssi__Reconnect;
typedef CHANNEL_REC *Irssi__Channel;
typedef QUERY_REC *Irssi__Query;
typedef NICK_REC *Irssi__Nick;

typedef WINDOW_REC *Irssi__Window;
typedef WI_ITEM_REC *Irssi__Windowitem;
