#ifndef IRSSI_IRC_DCC_DCC_SEND_H
#define IRSSI_IRC_DCC_DCC_SEND_H

#include <irssi/src/irc/dcc/dcc.h>

#define DCC_SEND(dcc) \
	MODULE_CHECK_CAST_MODULE(dcc, SEND_DCC_REC, type, "DCC", "SEND")

#define IS_DCC_SEND(dcc) \
	(DCC_SEND(dcc) ? TRUE : FALSE)

typedef struct {
#include <irssi/src/irc/dcc/dcc-file-rec.h>

	unsigned int file_quoted:1; /* file name was received quoted ("file name") */

	/* fastsending: */
	unsigned int waitforend:1; /* file is sent, just wait for the replies from the other side */
	unsigned int gotalldata:1; /* got all acks from the other end (needed to make sure the end of transfer works right) */
} SEND_DCC_REC;

#define DCC_SEND_TYPE module_get_uniq_id_str("DCC", "SEND")

void dcc_send_init(void);
void dcc_send_deinit(void);

#endif
