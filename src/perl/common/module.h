#define NEED_PERL_H
#define HAVE_CONFIG_H
#include "../module.h"
#include <XSUB.h>

#include "network.h"
#include "levels.h"
#include "commands.h"
#include "log.h"
#include "rawlog.h"
#include "ignore.h"
#include "settings.h"
#include "masks.h"
#include "special-vars.h"
#include "window-item-def.h"

#include "chat-protocols.h"
#include "chatnets.h"
#include "servers.h"
#include "servers-reconnect.h"
#include "servers-setup.h"
#include "channels.h"
#include "queries.h"
#include "nicklist.h"

#include "perl/perl-core.h"
#include "perl/perl-common.h"
#include "perl/perl-signals.h"
#include "perl/perl-sources.h"

typedef COMMAND_REC *Irssi__Command;
typedef LOG_REC *Irssi__Log;
typedef LOG_ITEM_REC *Irssi__Logitem;
typedef RAWLOG_REC *Irssi__Rawlog;
typedef IGNORE_REC *Irssi__Ignore;
typedef MODULE_REC *Irssi__Module;
typedef WI_ITEM_REC *Irssi__Windowitem;

typedef CHATNET_REC *Irssi__Chatnet;
typedef SERVER_REC *Irssi__Server;
typedef SERVER_CONNECT_REC *Irssi__Connect;
typedef RECONNECT_REC *Irssi__Reconnect;
typedef CHANNEL_REC *Irssi__Channel;
typedef QUERY_REC *Irssi__Query;
typedef NICK_REC *Irssi__Nick;
