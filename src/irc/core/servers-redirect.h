#ifndef __SERVERS_REDIRECT_H
#define __SERVERS_REDIRECT_H

/* Register new redirection command.

   remote - Specifies if the command is by default a remote command
   (eg. sent to another server). server_redirect_event() may override this.

   timeout - If remote is TRUE, specifies how many seconds to wait for
   reply before aborting.

   ... - char *start, int argpos, char *start, int argpos, ..., NULL,
         char *stop, int argpos, char *stop, int argpos, ..., NULL,
         char *optional, int argpos, ..., NULL
   List of events that start and stop this redirection.
   Start event list may be just NULL, but there must be at least one
   stop event. Optional events are checked only if they are received
   immediately after one of the stop-events. `argpos' specifies the
   word number in event string which is compared to wanted argument,
   -1 = don't compare, TRUE always. */
void server_redirect_register(const char *command,
			      int remote, int timeout, ...);
/* start/stop/opt lists shouldn't be free'd after, and their strings
   should be dynamically allocated */
void server_redirect_register_list(const char *command,
				   int remote, int timeout,
				   GSList *start, GSList *stop, GSList *opt);

/* Specify that the next command sent to server will be redirected.
   NOTE: This command MUST be called before irc_send_cmd().

   command - Specifies the registered command that should be used for this
   redirection.

   count - How many times to execute the redirection. Some commands may send
   multiple stop events, like MODE #a,#b.

   arg - The argument to be compared in event strings. You can give multiple
   arguments separated with space.

   remote - Specifies if the command is a remote command, -1 = use default.

   failure_signal - If irssi can't find the stop signal for the redirection,
   this signal is called.

   ... - char *event, char *redirect_signal, ..., NULL
   If the `event' is "", all the events belonging to the redirection but not
   specified here, will be sent there. */
void server_redirect_event(IRC_SERVER_REC *server, const char *command,
			   int count, const char *arg, int remote,
			   const char *failure_signal, ...);
/* Signals list shouldn't be free'd after, and it's strings should be
   dynamically allocated */
void server_redirect_event_list(IRC_SERVER_REC *server, const char *command,
				int count, const char *arg, int remote,
				const char *failure_signal, GSList *signals);

/* INTERNAL: */

/* irc_send_cmd() calls this to make sure redirecting knows
   what's sent to server */
void server_redirect_command(IRC_SERVER_REC *server, const char *command,
			     REDIRECT_REC *redirect);
/* Returns the redirection signal for specified event.
   This is the function that contains the real redirecting logic. */
const char *server_redirect_get_signal(IRC_SERVER_REC *server,
				       const char *prefix,
				       const char *event,
				       const char *args);
/* Returns the redirection signal for specified event.
   Doesn't change the server state in any way, so if you really wish to
   use the signal, call server_redirect_get_signal() after this.
   `redirected' is set to TRUE, if this event belongs to redirection even
   while there might be no redirection signal. */
const char *server_redirect_peek_signal(IRC_SERVER_REC *server,
					const char *prefix,
					const char *event,
					const char *args,
					int *redirected);

/* Destroy redirection record */
void server_redirect_destroy(REDIRECT_REC *rec);

void servers_redirect_init(void);
void servers_redirect_deinit(void);

#endif
