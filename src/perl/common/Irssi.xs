#include "module.h"

MODULE = Irssi  PACKAGE = Irssi

PROTOTYPES: ENABLE

void
init()
CODE:
	perl_api_version_check("Irssi");

void
deinit()
CODE:

BOOT:
        irssi_boot(Channel);
	irssi_boot(Core);
	irssi_boot(Ignore);
	irssi_boot(Log);
	irssi_boot(Masks);
	irssi_boot(Query);
	irssi_boot(Rawlog);
	irssi_boot(Server);
	irssi_boot(Settings);
