#ifndef __DCC_CHAT_H
#define __DCC_CHAT_H

#include "dcc.h"

DCC_REC *dcc_chat_find_id(const char *id);

void dcc_chat_init(void);
void dcc_chat_deinit(void);

#endif
