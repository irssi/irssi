#ifndef __SIGNAL_H
#define __SIGNAL_H

#define SIGNAL_MAX_ARGUMENTS 6
typedef void (*SIGNAL_FUNC) (gconstpointer, gconstpointer,
			     gconstpointer, gconstpointer,
			     gconstpointer, gconstpointer);

void signals_init(void);
void signals_deinit(void);

/* signal name -> ID */
#define signal_get_uniq_id(signal) \
        module_get_uniq_id_str("signals", signal)
/* signal ID -> name */
#define signal_get_id_str(signal_id) \
	module_find_id_str("signals", signal_id)

/* bind a signal */
void signal_add_to(const char *module, int pos,
		   const char *signal, SIGNAL_FUNC func);
void signal_add_to_id(const char *module, int pos,
		      int signal, SIGNAL_FUNC func);
#define signal_add(a, b) signal_add_to(MODULE_NAME, 1, a, b)
#define signal_add_first(a, b) signal_add_to(MODULE_NAME, 0, a, b)
#define signal_add_last(a, b) signal_add_to(MODULE_NAME, 2, a, b)

/* unbind signal */
void signal_remove(const char *signal, SIGNAL_FUNC func);
void signal_remove_id(int signal_id, SIGNAL_FUNC func);

/* emit signal */
int signal_emit(const char *signal, int params, ...);
int signal_emit_id(int signal_id, int params, ...);

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

/* remove all signals that belong to `module' */
void signals_remove_module(const char *module);

#endif
