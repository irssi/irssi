#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#undef _
#undef VERSION
#define HAVE_CONFIG_H
#include "../module.h"

#include "network.h"
#include "commands.h"
#include "log.h"
#include "rawlog.h"
#include "ignore.h"
#include "settings.h"
#include "masks.h"

#include "chatnets.h"
#include "servers.h"
#include "servers-reconnect.h"
#include "servers-redirect.h"
#include "servers-setup.h"
#include "channels.h"
#include "queries.h"
#include "nicklist.h"

#include "fe-common/core/fe-windows.h"
#include "fe-common/core/formats.h"
#include "fe-common/core/printtext.h"
#include "fe-common/core/window-items.h"
#include "fe-common/core/themes.h"
#include "fe-common/core/keyboard.h"

#include "perl/perl-common.h"
#include "perl/perl-signals.h"

typedef COMMAND_REC *Irssi__Command;
typedef LOG_REC *Irssi__Log;
typedef LOG_ITEM_REC *Irssi__Logitem;
typedef RAWLOG_REC *Irssi__Rawlog;
typedef IGNORE_REC *Irssi__Ignore;
typedef MODULE_REC *Irssi__Module;

typedef CHATNET_REC *Irssi__Chatnet;
typedef SERVER_REC *Irssi__Server;
typedef SERVER_CONNECT_REC *Irssi__Connect;
typedef RECONNECT_REC *Irssi__Reconnect;
typedef CHANNEL_REC *Irssi__Channel;
typedef QUERY_REC *Irssi__Query;
typedef NICK_REC *Irssi__Nick;

typedef THEME_REC *Irssi__Theme;
typedef KEYINFO_REC *Irssi__Keyinfo;
typedef WINDOW_REC *Irssi__Window;
typedef WI_ITEM_REC *Irssi__Windowitem;
