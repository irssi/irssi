#ifndef __DCC_GET_H
#define __DCC_GET_H

#include "dcc.h"

#define DCC_GET(dcc) \
	MODULE_CHECK_CAST_MODULE(dcc, GET_DCC_REC, type, "DCC", "GET")

#define IS_DCC_GET(dcc) \
	(DCC_GET(dcc) ? TRUE : FALSE)

enum {
	DCC_GET_DEFAULT,

	DCC_GET_RENAME,
	DCC_GET_OVERWRITE,
	DCC_GET_RESUME
};

typedef struct {
#include "dcc-file-rec.h"

	int get_type; /* what to do if file exists? */
	char *file; /* file name we're really moving, arg is just the reference */

	unsigned int file_quoted:1; /* file name was received quoted ("file name") */
	unsigned int from_dccserver:1; /* get is using dccserver method */
} GET_DCC_REC;

#define DCC_GET_TYPE module_get_uniq_id_str("DCC", "GET")

typedef void (*DCC_GET_FUNC) (GET_DCC_REC *);

/* handle receiving DCC - GET/RESUME. */
void cmd_dcc_receive(const char *data, DCC_GET_FUNC accept_func,
		     DCC_GET_FUNC pasv_accept_func);

void dcc_get_passive(GET_DCC_REC *dcc);
void dcc_get_connect(GET_DCC_REC *dcc);
char *dcc_get_download_path(const char *fname);

void dcc_get_init(void);
void dcc_get_deinit(void);

#endif
