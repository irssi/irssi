#ifndef __LOG_H
#define __LOG_H

enum {
        LOG_ROTATE_NEVER,
	LOG_ROTATE_HOURLY,
	LOG_ROTATE_DAILY,
	LOG_ROTATE_WEEKLY,
	LOG_ROTATE_MONTHLY
};

typedef struct {
	char *fname; /* file name */
	int handle; /* file handle */
	time_t opened;

	int level; /* log only these levels */
	char **items; /* log only on these items (channels, queries, window refnums) */

	time_t last; /* when last message was written */
	int rotate;

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

const char *log_rotate2str(int rotate);
int log_str2rotate(const char *str);

int log_start_logging(LOG_REC *log);
void log_stop_logging(LOG_REC *log);

void log_init(void);
void log_deinit(void);

#endif
