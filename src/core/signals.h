#ifndef __SIGNAL_H
#define __SIGNAL_H

#define SIGNAL_PRIORITY_LOW    	100
#define SIGNAL_PRIORITY_DEFAULT	0
#define SIGNAL_PRIORITY_HIGH	-100

#define SIGNAL_MAX_ARGUMENTS 6
typedef void (*SIGNAL_FUNC) (const void *, const void *,
			     const void *, const void *,
			     const void *, const void *);

extern void *signal_user_data; /* use signal_get_user_data() macro to access */

/* bind a signal */
void signal_add_full(const char *module, int priority,
		     const char *signal, SIGNAL_FUNC func, void *user_data);
void signal_add_full_id(const char *module, int priority,
			int signal, SIGNAL_FUNC func, void *user_data);
#define signal_add(signal, func) \
	signal_add_full(MODULE_NAME, SIGNAL_PRIORITY_DEFAULT, (signal), (SIGNAL_FUNC) (func), NULL)
#define signal_add_first(signal, func) \
	signal_add_full(MODULE_NAME, SIGNAL_PRIORITY_HIGH, (signal), (SIGNAL_FUNC) (func), NULL)
#define signal_add_last(signal, func) \
	signal_add_full(MODULE_NAME, SIGNAL_PRIORITY_LOW, (signal), (SIGNAL_FUNC) (func), NULL)

#define signal_add_data(signal, func, data) \
	signal_add_full(MODULE_NAME, SIGNAL_PRIORITY_DEFAULT, (signal), (SIGNAL_FUNC) (func), data)
#define signal_add_first_data(signal, func, data) \
	signal_add_full(MODULE_NAME, SIGNAL_PRIORITY_HIGH, (signal), (SIGNAL_FUNC) (func), data)
#define signal_add_last_data(signal, func, data) \
	signal_add_full(MODULE_NAME, SIGNAL_PRIORITY_LOW, (signal), (SIGNAL_FUNC) (func), data)

/* unbind signal */
void signal_remove_full(const char *signal, SIGNAL_FUNC func, void *user_data);
#define signal_remove(signal, func) \
        signal_remove_full((signal), (SIGNAL_FUNC) (func), NULL)
#define signal_remove_data(signal, func, data) \
        signal_remove_full((signal), (SIGNAL_FUNC) (func), data)
void signal_remove_id(int signal_id, SIGNAL_FUNC func, void *user_data);

/* emit signal */
int signal_emit(const char *signal, int params, ...);
int signal_emit_id(int signal_id, int params, ...);

/* continue currently emitted signal with different parameters */
void signal_continue(int params, ...);

/* stop the current ongoing signal emission */
void signal_stop(void);
/* stop ongoing signal emission by signal name */
void signal_stop_by_name(const char *signal);

/* return the name of the signal that is currently being emitted */
const char *signal_get_emitted(void);
/* return the ID of the signal that is currently being emitted */
int signal_get_emitted_id(void);
/* return TRUE if specified signal was stopped */
int signal_is_stopped(int signal_id);
/* return the user data of the signal function currently being emitted */
#define signal_get_user_data() signal_user_data

/* remove all signals that belong to `module' */
void signals_remove_module(const char *module);

/* signal name -> ID */
#define signal_get_uniq_id(signal) \
        module_get_uniq_id_str("signals", signal)
/* signal ID -> name */
#define signal_get_id_str(signal_id) \
	module_find_id_str("signals", signal_id)

void signals_init(void);
void signals_deinit(void);

#endif
