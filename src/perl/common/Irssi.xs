#include "module.h"
#include "levels.h"

MODULE = Irssi  PACKAGE = Irssi

PROTOTYPES: ENABLE

INCLUDE: Channel.xs
INCLUDE: Core.xs
INCLUDE: Log.xs
INCLUDE: Masks.xs
INCLUDE: Query.xs
INCLUDE: Rawlog.xs
INCLUDE: Server.xs
INCLUDE: Settings.xs
INCLUDE: Window.xs
