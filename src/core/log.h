#ifndef __LOG_H
#define __LOG_H

enum {
	LOG_ITEM_TARGET, /* channel, query, .. */
	LOG_ITEM_WINDOW_REFNUM
};

typedef char *(*COLORIZE_FUNC)(const char *str);

typedef struct _LOG_REC LOG_REC;
typedef struct _LOG_ITEM_REC LOG_ITEM_REC;

struct _LOG_ITEM_REC {
	int type;
        char *name;
	char *servertag;
};

struct _LOG_REC {
	char *fname; /* file name, in strftime() format */
	char *real_fname; /* the current expanded file name */
	int handle; /* file handle */
	time_t opened;

	int level; /* log only these levels */
	GSList *items; /* log only on these items */

	time_t last; /* when last message was written */
        COLORIZE_FUNC colorizer;

	unsigned int autoopen:1; /* automatically start logging at startup */
	unsigned int failed:1; /* opening log failed last time */
	unsigned int temp:1; /* don't save this to config file */
};

extern GSList *logs;

/* Create log record - you still need to call log_update() to actually add it
   into log list */
LOG_REC *log_create_rec(const char *fname, int level);
void log_update(LOG_REC *log);
void log_close(LOG_REC *log);
LOG_REC *log_find(const char *fname);

void log_item_add(LOG_REC *log, int type, const char *name,
		  const char *servertag);
void log_item_destroy(LOG_REC *log, LOG_ITEM_REC *item);
LOG_ITEM_REC *log_item_find(LOG_REC *log, int type, const char *item,
			    const char *servertag);

void log_file_write(const char *server_tag, const char *item, int level,
		    const char *str, int no_fallbacks);
void log_write_rec(LOG_REC *log, const char *str, int level);

int log_start_logging(LOG_REC *log);
void log_stop_logging(LOG_REC *log);

void log_init(void);
void log_deinit(void);

#endif
