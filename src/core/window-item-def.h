#ifndef IRSSI_CORE_WINDOW_ITEM_DEF_H
#define IRSSI_CORE_WINDOW_ITEM_DEF_H

#include <irssi/src/common.h>
#include <irssi/src/core/servers.h>

#define STRUCT_SERVER_REC SERVER_REC
struct _WI_ITEM_REC {
#include <irssi/src/core/window-item-rec.h>
};

#endif
