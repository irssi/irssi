#ifndef IRSSI_FE_TEXT_STATUSBAR_CONFIG_H
#define IRSSI_FE_TEXT_STATUSBAR_CONFIG_H

#include <irssi/src/fe-text/statusbar.h>

void statusbar_config_destroy(STATUSBAR_GROUP_REC *group,
			      STATUSBAR_CONFIG_REC *config);

void statusbar_config_init(void);
void statusbar_config_deinit(void);

#endif
