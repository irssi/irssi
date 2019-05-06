#define NEED_PERL_H
#define HAVE_CONFIG_H
#include <irssi/src/perl/module.h>
#include <XSUB.h>

#include <irssi/src/core/network.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/log.h>
#include <irssi/src/core/rawlog.h>
#include <irssi/src/core/ignore.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/masks.h>
#include <irssi/src/core/special-vars.h>
#include <irssi/src/core/window-item-def.h>

#include <irssi/src/core/chat-protocols.h>
#include <irssi/src/core/chatnets.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/servers-reconnect.h>
#include <irssi/src/core/servers-setup.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/queries.h>
#include <irssi/src/core/nicklist.h>

#include <irssi/src/perl/perl-core.h>
#include <irssi/src/perl/perl-common.h>
#include <irssi/src/perl/perl-signals.h>
#include <irssi/src/perl/perl-sources.h>

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
