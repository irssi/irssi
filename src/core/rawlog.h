#ifndef __RAWLOG_H
#define __RAWLOG_H

struct _RAWLOG_REC {
	int logging;
	int handle;

        int nlines;
	GSList *lines;
};

RAWLOG_REC *rawlog_create(void);
void rawlog_destroy(RAWLOG_REC *rawlog);

void rawlog_input(RAWLOG_REC *rawlog, const char *str);
void rawlog_output(RAWLOG_REC *rawlog, const char *str);
void rawlog_redirect(RAWLOG_REC *rawlog, const char *str);

void rawlog_set_size(int lines);

void rawlog_open(RAWLOG_REC *rawlog, const char *fname);
void rawlog_close(RAWLOG_REC *rawlog);
void rawlog_save(RAWLOG_REC *rawlog, const char *fname);

void rawlog_init(void);
void rawlog_deinit(void);

#endif
