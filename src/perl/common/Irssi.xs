#include "module.h"

MODULE = Irssi  PACKAGE = Irssi

PROTOTYPES: ENABLE

void
init()
CODE:
	perl_api_version_check("Irssi");

INCLUDE: Channel.xs
INCLUDE: Core.xs
INCLUDE: Ignore.xs
INCLUDE: Log.xs
INCLUDE: Masks.xs
INCLUDE: Query.xs
INCLUDE: Rawlog.xs
INCLUDE: Server.xs
INCLUDE: Settings.xs
