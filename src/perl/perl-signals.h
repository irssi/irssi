#ifndef __PERL_SIGNALS_H
#define __PERL_SIGNALS_H

void perl_signal_add_to(const char *signal, const char *func, int priority);
#define perl_signal_add_first(signal, func) \
        perl_signal_add_to(signal, func, 0)
#define perl_signal_add(signal, func) \
        perl_signal_add_to(signal, func, 1)
#define perl_signal_add_last(signal, func) \
        perl_signal_add_to(signal, func, 2)

void perl_signal_remove(const char *signal, const char *func);

/* destroy all signals used by package */
void perl_signals_package_destroy(const char *package);

void perl_signals_start(void);
void perl_signals_stop(void);

void perl_signals_init(void);
void perl_signals_deinit(void);

#endif
