#ifndef __PIDWAIT_H
#define __PIDWAIT_H

void pidwait_init(void);
void pidwait_deinit(void);

/* add a pid to wait list */
void pidwait_add(int pid);
/* remove pid from wait list */
void pidwait_remove(int pid);

/* return list of pids that are being waited.
   don't free the return value. */
GSList *pidwait_get_pids(void);

#endif
