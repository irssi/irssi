#ifndef __PIDWAIT_H
#define __PIDWAIT_H

void pidwait_init(void);
void pidwait_deinit(void);

/* add a pid to wait list */
void pidwait_add(int pid);
/* remove pid from wait list */
void pidwait_remove(int pid);

#endif
