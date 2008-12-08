#ifndef __PERL_SIGNALS_H
#define __PERL_SIGNALS_H

void perl_signal_args_to_c(void (*callback)(void *, void **), void *cb_arg,
                           int signal_id, SV **args, size_t n_args);

void perl_signal_add_full(const char *signal, SV *func, int priority);

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

void perl_command_runsub(const char *cmd, const char *data, 
			 SERVER_REC *server, WI_ITEM_REC *item);

void perl_signal_register(const char *signal, const char **args);

void perl_signals_start(void);
void perl_signals_stop(void);

void perl_signals_init(void);
void perl_signals_deinit(void);

#endif
