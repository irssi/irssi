#ifndef __STATUSBAR_CONFIG_H
#define __STATUSBAR_CONFIG_H

#include "statusbar.h"

void statusbar_config_destroy(STATUSBAR_GROUP_REC *group,
			      STATUSBAR_CONFIG_REC *config);

void statusbar_config_init(void);
void statusbar_config_deinit(void);

#endif
