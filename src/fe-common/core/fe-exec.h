#ifndef __FE_EXEC_H
#define __FE_EXEC_H

#include "fe-windows.h"

#define EXEC_WI(query) \
	MODULE_CHECK_CAST_MODULE(query, EXEC_WI_REC, type, \
			      "WINDOW ITEM TYPE", "EXEC")

#define IS_EXEC_WI(query) \
	(EXEC_WI(query) ? TRUE : FALSE)

typedef struct PROCESS_REC PROCESS_REC;

#define STRUCT_SERVER_REC void
typedef struct {
#include "window-item-rec.h"
	PROCESS_REC *process;
	unsigned int destroying:1;
} EXEC_WI_REC;

struct PROCESS_REC {
        int id;
	char *name;
        char *args;

	int pid;
	GIOChannel *in;
        NET_SENDBUF_REC *out;
        LINEBUF_REC *databuf;
	int read_tag;

        char *target; /* send text with /msg <target> ... */
	WINDOW_REC *target_win; /* print text to this window */
        EXEC_WI_REC *target_item; /* print text to this exec window item */

	unsigned int shell:1; /* start the program via /bin/sh */
	unsigned int notice:1; /* send text with /notice, not /msg if target is set */
	unsigned int silent:1; /* don't print "process exited with level xx" */
};

void fe_exec_init(void);
void fe_exec_deinit(void);

#endif
