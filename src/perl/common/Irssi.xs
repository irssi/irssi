#include "module.h"

static int initialized = FALSE;

void perl_expando_init(void);
void perl_expando_deinit(void);

void perl_settings_init(void);
void perl_settings_deinit(void);

MODULE = Irssi  PACKAGE = Irssi

PROTOTYPES: ENABLE

void
init()
CODE:
	if (initialized) return;
	perl_api_version_check("Irssi");
	initialized = TRUE;

        perl_settings_init();
	perl_expando_init();

void
deinit()
CODE:
	if (!initialized) return;
	perl_expando_deinit();
        perl_settings_deinit();
	initialized = FALSE;

BOOT:
        irssi_boot(Channel);
	irssi_boot(Core);
	irssi_boot(Expando);
	irssi_boot(Ignore);
	irssi_boot(Log);
	irssi_boot(Masks);
	irssi_boot(Query);
	irssi_boot(Rawlog);
	irssi_boot(Server);
	irssi_boot(Settings);
