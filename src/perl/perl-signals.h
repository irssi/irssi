#ifndef __PERL_SIGNALS_H
#define __PERL_SIGNALS_H

void perl_signal_add_to(const char *signal, SV *func, int priority);
#define perl_signal_add_first(signal, func) \
        perl_signal_add_to(signal, func, 0)
#define perl_signal_add(signal, func) \
        perl_signal_add_to(signal, func, 1)
#define perl_signal_add_last(signal, func) \
        perl_signal_add_to(signal, func, 2)

void perl_signal_remove(const char *signal, SV *func);
/* remove all signals used by script */
void perl_signal_remove_script(PERL_SCRIPT_REC *script);

void perl_command_bind_to(const char *cmd, const char *category,
			  SV *func, int priority);
#define perl_command_bind_first(cmd, category, func) \
        perl_command_bind_to(cmd, category, func, 0)
#define perl_command_bind(cmd, category, func) \
        perl_command_bind_to(cmd, category, func, 1)
#define perl_command_bind_last(cmd, category, func) \
        perl_command_bind_to(cmd, category, func, 2)

void perl_command_unbind(const char *cmd, SV *func);

void perl_signals_start(void);
void perl_signals_stop(void);

void perl_signals_init(void);
void perl_signals_deinit(void);

#endif
