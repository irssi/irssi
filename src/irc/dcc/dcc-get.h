#ifndef __DCC_GET_H
#define __DCC_GET_H

#include "dcc.h"

enum {
	DCC_GET_DEFAULT,

	DCC_GET_RENAME,
	DCC_GET_OVERWRITE,
	DCC_GET_RESUME
};

typedef void (*DCC_GET_FUNC) (DCC_REC *);

/* handle receiving DCC - GET/RESUME. */
void cmd_dcc_receive(const char *data, DCC_GET_FUNC accept);

void dcc_get_connect(DCC_REC *dcc);
char *dcc_get_download_path(const char *fname);

#define dcc_is_waiting_get(dcc) \
        ((dcc)->type == DCC_TYPE_GET && dcc_is_waiting_user(dcc))

void dcc_get_init(void);
void dcc_get_deinit(void);

#endif
