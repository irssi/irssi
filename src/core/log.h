#ifndef __LOG_H
#define __LOG_H

typedef struct {
	char *fname; /* file name, in strftime() format */
	char *real_fname; /* the current expanded file name */
	int handle; /* file handle */
	time_t opened;

	int level; /* log only these levels */
	char **items; /* log only on these items (channels, queries, window refnums) */

	time_t last; /* when last message was written */

	int autoopen:1; /* automatically start logging at startup */
	int temp:1; /* don't save this to config file */
} LOG_REC;

extern GSList *logs;

/* Create log record - you still need to call log_update() to actually add it
   into log list */
LOG_REC *log_create_rec(const char *fname, int level, const char *items);
void log_update(LOG_REC *log);
void log_close(LOG_REC *log);

LOG_REC *log_find(const char *fname);

void log_write(const char *item, int level, const char *str);
void log_write_rec(LOG_REC *log, const char *str);

int log_start_logging(LOG_REC *log);
void log_stop_logging(LOG_REC *log);

void log_init(void);
void log_deinit(void);

#endif
