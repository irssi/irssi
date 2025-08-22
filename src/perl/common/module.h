#define NEED_PERL_H
#define HAVE_CONFIG_H
#include <irssip/src/perl/module.h>
#include <XSUB.h>

#include <irssip/src/core/network.h>
#include <irssip/src/core/levels.h>
#include <irssip/src/core/commands.h>
#include <irssip/src/core/log.h>
#include <irssip/src/core/rawlog.h>
#include <irssip/src/core/ignore.h>
#include <irssip/src/core/settings.h>
#include <irssip/src/core/masks.h>
#include <irssip/src/core/special-vars.h>
#include <irssip/src/core/window-item-def.h>

#include <irssip/src/core/chat-protocols.h>
#include <irssip/src/core/chatnets.h>
#include <irssip/src/core/servers.h>
#include <irssip/src/core/servers-reconnect.h>
#include <irssip/src/core/servers-setup.h>
#include <irssip/src/core/channels.h>
#include <irssip/src/core/queries.h>
#include <irssip/src/core/nicklist.h>

#include <irssip/src/perl/perl-core.h>
#include <irssip/src/perl/perl-common.h>
#include <irssip/src/perl/perl-signals.h>
#include <irssip/src/perl/perl-sources.h>

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
