#ifndef __SIGNAL_H
#define __SIGNAL_H

typedef void (*SIGNAL_FUNC) (gconstpointer, gconstpointer, gconstpointer, gconstpointer, gconstpointer, gconstpointer, gconstpointer);

void signals_init(void);
void signals_deinit(void);

/* use this macro to convert the signal name to ID */
#define signal_get_uniq_id(signal) \
        module_get_uniq_id_str("signals", signal)

/* bind a signal */
void signal_add_to(const char *module, int pos, const char *signal, SIGNAL_FUNC func);
#define signal_add(a, b) signal_add_to(MODULE_NAME, 1, a, b)
#define signal_add_first(a, b) signal_add_to(MODULE_NAME, 0, a, b)
#define signal_add_last(a, b) signal_add_to(MODULE_NAME, 2, a, b)

/* unbind signal */
void signal_remove(const char *signal, SIGNAL_FUNC func);

/* emit signal */
int signal_emit(const char *signal, int params, ...);
int signal_emit_id(int signal_id, int params, ...);

/* stop the current ongoing signal emission */
void signal_stop(void);
/* stop ongoing signal emission by signal name */
void signal_stop_by_name(const char *signal);

/* remove all signals that belong to `module' */
void signals_remove_module(const char *module);

#endif
