/*
 server-redirect.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "misc.h"

#include "irc-servers.h"
#include "servers-redirect.h"

typedef struct {
	int refcount;

	int remote;
	int timeout;
	GSList *start, *stop; /* char *event, int argpos, ... */
} REDIRECT_CMD_REC;

struct _REDIRECT_REC {
	REDIRECT_CMD_REC *cmd;
	time_t created;
        int destroyed;

	char *arg;
        int remote;
	char *failure_signal, *default_signal;
	GSList *signals; /* event, signal, ... */
};

static GHashTable *command_redirects; /* "command xxx" : REDIRECT_CMD_REC* */

/* Find redirection command record for specified command line. */
static REDIRECT_CMD_REC *redirect_cmd_find(const char *command)
{
        REDIRECT_CMD_REC *rec;
	const char *p;
        char *cmd;

	p = strchr(command, ' ');
	if (p == NULL)
                rec = g_hash_table_lookup(command_redirects, command);
	else {
		cmd = g_strndup(command, (int) (p-command));
                rec = g_hash_table_lookup(command_redirects, cmd);
		g_free(cmd);
	}
        return rec;
}

static void redirect_cmd_destroy(REDIRECT_CMD_REC *rec)
{
	GSList *tmp;

	for (tmp = rec->start; tmp != NULL; tmp = tmp->next->next)
                g_free(tmp->data);
	for (tmp = rec->stop; tmp != NULL; tmp = tmp->next->next)
                g_free(tmp->data);
        g_slist_free(rec->start);
        g_slist_free(rec->stop);
        g_free(rec);
}

static void redirect_cmd_ref(REDIRECT_CMD_REC *rec)
{
        rec->refcount++;
}

static void redirect_cmd_unref(REDIRECT_CMD_REC *rec)
{
	if (--rec->refcount <= 0)
                redirect_cmd_destroy(rec);
}

void server_redirect_destroy(REDIRECT_REC *rec)
{
	redirect_cmd_unref(rec->cmd);

	g_free_not_null(rec->arg);
        g_free_not_null(rec->failure_signal);
        g_free_not_null(rec->default_signal);
	g_slist_foreach(rec->signals, (GFunc) g_free, NULL);
	g_slist_free(rec->signals);
        g_free(rec);
}

void server_redirect_register(const char *command,
			      int remote, int timeout, ...)
{
	va_list va;
	GSList *start, *stop, **list;
	const char *event;
        int argpos;

	va_start(va, timeout);
	start = stop = NULL; list = &start;
	for (;;) {
		event = va_arg(va, const char *);
		if (event == NULL) {
			if (list == &stop)
				break;
			list = &stop;
                        continue;
		}

                argpos = va_arg(va, int);
		*list = g_slist_append(*list, g_strdup(event));
		*list = g_slist_append(*list, GINT_TO_POINTER(argpos));
	}

	va_end(va);

	server_redirect_register_list(command, remote, timeout, start, stop);
}

void server_redirect_register_list(const char *command,
				   int remote, int timeout,
				   GSList *start, GSList *stop)
{
	REDIRECT_CMD_REC *rec;
        gpointer key, value;

        g_return_if_fail(command != NULL);
        g_return_if_fail(stop != NULL);

	if (g_hash_table_lookup_extended(command_redirects, command,
					 &key, &value)) {
		/* Already registered - might have changed so destroy
		   the old one */
		g_hash_table_remove(command_redirects, command);
                redirect_cmd_unref(value);
		g_free(key);
	}

	rec = g_new0(REDIRECT_CMD_REC, 1);
        redirect_cmd_ref(rec);
	rec->remote = remote;
	rec->timeout = timeout;
	rec->start = start;
        rec->stop = stop;
        g_hash_table_insert(command_redirects, g_strdup(command), rec);
}

void server_redirect_event(IRC_SERVER_REC *server, const char *command,
			   const char *arg, int remote,
			   const char *failure_signal, ...)
{
	GSList *signals;
        const char *event, *signal;
	va_list va;

	va_start(va, failure_signal);
	signals = NULL;
	while ((event = va_arg(va, const char *)) != NULL) {
		signal = va_arg(va, const char *);
		if (signal == NULL) {
			g_warning("server_redirect_event(%s): "
				  "signal not specified for event", command);
			break;
		}

		signals = g_slist_append(signals, g_strdup(event));
		signals = g_slist_append(signals, g_strdup(signal));
	}

	va_end(va);

	server_redirect_event_list(server, command, arg, remote,
				   failure_signal, signals);
}

void server_redirect_event_list(IRC_SERVER_REC *server, const char *command,
				const char *arg, int remote,
				const char *failure_signal, GSList *signals)
{
	REDIRECT_CMD_REC *cmdrec;
	REDIRECT_REC *rec;
	GSList *default_signal;
        char *default_signal_key;

	g_return_if_fail(IS_IRC_SERVER(server));
	g_return_if_fail(command != NULL);
        g_return_if_fail((g_slist_length(signals) & 1) == 0);

	if (server->redirect_next != NULL) {
		server_redirect_destroy(server->redirect_next);
                server->redirect_next = NULL;
	}

	cmdrec = g_hash_table_lookup(command_redirects, command);
	if (cmdrec == NULL) {
		g_warning("Unknown redirection command: %s", command);
                return;
	}

	redirect_cmd_ref(cmdrec);

        rec = g_new0(REDIRECT_REC, 1);
        rec->created = time(NULL);
        rec->cmd = cmdrec;
	rec->arg = g_strdup(arg);
	rec->remote = remote != -1 ? remote : cmdrec->remote;
	rec->failure_signal = g_strdup(failure_signal);

	default_signal = gslist_find_string(signals, "");
	if (default_signal != NULL) {
                default_signal_key = default_signal->data;
		rec->default_signal = default_signal->next->data;

                signals = g_slist_remove(signals, default_signal_key);
		signals = g_slist_remove(signals, rec->default_signal);
                g_free(default_signal_key);
	}
	rec->signals = signals;

        server->redirect_next = rec;
}

void server_redirect_command(IRC_SERVER_REC *server, const char *command,
			     REDIRECT_REC *redirect)
{
        REDIRECT_CMD_REC *cmdrec;

	g_return_if_fail(IS_IRC_SERVER(server));
	g_return_if_fail(command != NULL);

	if (redirect == NULL) {
		cmdrec = redirect_cmd_find(command);
		if (cmdrec == NULL)
			return;

		/* no redirection wanted, but still register the command
		   so future redirections wont get messed up. */
		redirect_cmd_ref(cmdrec);

		redirect = g_new0(REDIRECT_REC, 1);
		redirect->created = time(NULL);
		redirect->cmd = cmdrec;
		redirect->remote = cmdrec->remote;
	}

	server->redirects = g_slist_append(server->redirects, redirect);
}

static int redirect_args_match(const char *event_args,
			       const char *arg, int pos)
{
	const char *start;

	if (pos == -1)
		return TRUE;

        /* skip to the start of the wanted argument */
	while (pos > 0 && *event_args != '\0') {
                while (*event_args != ' ' && *event_args != '\0') event_args++;
		while (*event_args == ' ') event_args++;
                pos--;
	}

	/* now compare the arguments */
	start = event_args;
	while (*arg != '\0') {
		while (*arg != '\0' && *arg != ' ' && *event_args != '\0') {
			if (*arg != *event_args)
				break;
			arg++; event_args++;
		}

		if ((*arg == '\0' || *arg == ' ') &&
		    (*event_args == '\0' || *event_args == ' '))
			return TRUE;

                /* compare the next argument */
		while (*arg != ' ' && *arg != '\0') arg++;
                while (*arg == ' ') arg++;

		event_args = start;
	}

        return FALSE;
}

static GSList *redirect_cmd_list_find(GSList *list, const char *event)
{
	while (list != NULL) {
		const char *str = list->data;

		if (strcmp(str, event) == 0)
                        break;
                list = list->next->next;
	}

        return list;
}

static const char *redirect_match(REDIRECT_REC *redirect, const char *event,
				  const char *args, int *match_stop)
{
	GSList *tmp, *cmdpos;
        const char *signal;
        int stop_signal;

	/* get the signal for redirection event - if it's not found we'll
	   use the default signal */
        signal = NULL;
	for (tmp = redirect->signals; tmp != NULL; tmp = tmp->next->next) {
		if (strcmp(tmp->data, event) == 0) {
			signal = tmp->next->data;
			break;
		}
	}

	/* find the argument position */
	cmdpos = redirect_cmd_list_find(redirect->cmd->start, event);
	if (cmdpos != NULL)
		stop_signal = FALSE;
	else {
		cmdpos = redirect_cmd_list_find(redirect->cmd->stop,
						event);
		stop_signal = cmdpos != NULL;
	}

	if (signal == NULL && cmdpos == NULL) {
		/* event not found from specified redirection events nor
		   registered command events */
		return NULL;
	}

	/* check that arguments match */
	if (args != NULL && redirect->arg != NULL && cmdpos != NULL &&
	    !redirect_args_match(args, redirect->arg,
				 GPOINTER_TO_INT(cmdpos->next->data)))
		return NULL;

	*match_stop = stop_signal;
	return signal != NULL ? signal : redirect->default_signal;
}

static REDIRECT_REC *redirect_find(IRC_SERVER_REC *server, const char *event,
				   const char *args, const char **signal,
				   int *match_stop)
{
        REDIRECT_REC *redirect;
	GSList *tmp, *next;
	time_t now;

	/* find the redirection */
	*signal = NULL; redirect = NULL;
	for (tmp = server->redirects; tmp != NULL; tmp = tmp->next) {
		REDIRECT_REC *rec = tmp->data;

		*signal = redirect_match(rec, event, args, match_stop);
		if (*signal != NULL) {
			redirect = rec;
			break;
		}
	}

	/* remove the destroyed, non-remote and timeouted remote
	   redirections that should have happened before this redirection */
	now = time(NULL);
	for (tmp = server->redirects; tmp != NULL; tmp = next) {
		REDIRECT_REC *rec = tmp->data;

		if (rec == redirect)
			break;

                next = tmp->next;
		if (rec->destroyed ||
		    (rec->remote && (now-rec->created) > rec->cmd->timeout) ||
		    (redirect != NULL && !rec->remote)) {
			server->redirects =
				g_slist_remove(server->redirects, rec);
			if (!rec->destroyed && rec->failure_signal != NULL) {
				/* emit the failure signal */
				signal_emit(rec->failure_signal, 1, server);
			}
			server_redirect_destroy(rec);
		}
	}

        return redirect;
}

const char *server_redirect_get_signal(IRC_SERVER_REC *server,
				       const char *event,
				       const char *args)
{
        REDIRECT_REC *redirect;
        const char *signal;
	int match_stop;

	if (server->redirects == NULL)
		return NULL;

        match_stop = FALSE;
	if (server->redirect_continue == NULL) {
                /* find the redirection */
		redirect = redirect_find(server, event, args,
					 &signal, &match_stop);
	} else {
		/* redirection is already started, now we'll just need to
		   keep redirecting until stop-event is found. */
		redirect = server->redirect_continue;
		signal = redirect_match(redirect, event, NULL, &match_stop);
		if (signal == NULL) {
			/* unknown event - redirect to the default signal.
			   FIXME: if stop event isn't properly got, this
			   could break everything. Add some checks that if
			   we get eg. 10 different unknown events after this,
			   or if one of them matches to another redirection,
			   abort this. */
			signal = redirect->default_signal;
		}
	}

	if (!match_stop || redirect == NULL)
		server->redirect_continue = redirect;
	else {
		/* stop event - remove this redirection next time this
		   function is called (can't destroy now or our return
		   value would be corrupted) */
                redirect->destroyed = TRUE;
		server->redirect_continue = NULL;
	}

        return signal;
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	if (!IS_IRC_SERVER(server))
                return;

	g_slist_foreach(server->redirects,
			(GFunc) server_redirect_destroy, NULL);
	g_slist_free(server->redirects);

	if (server->redirect_next != NULL)
		server_redirect_destroy(server->redirect_next);
}

static void cmd_redirect_destroy(char *key, REDIRECT_CMD_REC *cmd)
{
	g_free(key);
        redirect_cmd_unref(cmd);
}

void servers_redirect_init(void)
{
	command_redirects = g_hash_table_new((GHashFunc) g_str_hash, (GCompareFunc) g_str_equal);

	/* WHOIS - register as remote command by default
	   with a timeout of one minute */
	server_redirect_register("whois", TRUE, 60,
				 "event 311", 1, /* Begins the WHOIS */
                                 "event 401", 1, /* No such nick */
				 NULL,
				 "event 318", 1, /* End of WHOIS */
                                 "event 402", 1, /* No such server */
				 NULL);

	/* WHOWAS */
	server_redirect_register("whowas", FALSE, 0,
				 "event 314", 1, /* Begins the WHOWAS */
                                 "event 406", 1, /* There was no such nick */
				 NULL,
				 "event 369", 1, /* End of WHOWAS */
				 NULL);

	/* WHO */
	server_redirect_register("who", FALSE, 0,
				 "event 352", 1, /* Begins the WHO */
                                 "event 401", 1, /* No such nick/channel */
				 NULL,
				 "event 315", 1, /* End of WHO */
				 "event 403", 1, /* no such channel */
				 NULL);

        /* LIST */
	server_redirect_register("list", FALSE, 0,
				 "event 321", 1, /* Begins the LIST */
				 NULL,
				 "event 323", 1, /* End of LIST */
				 NULL);

        /* ISON */
	server_redirect_register("ison", FALSE, 0,
				 NULL,
				 "event 303", 1, /* ISON */
				 NULL);

        /* USERHOST */
	server_redirect_register("userhost", FALSE, 0,
				 "event 401", 1, /* no such nick */
				 NULL,
				 "event 302", 1, /* Userhost */
				 "event 461", 1, /* Not enough parameters */
				 NULL);

	/* MODE #channel */
	server_redirect_register("mode channel", FALSE, 0,
				 NULL,
				 "event 324", 1, /* MODE-reply */
				 "event 403", 1, /* no such channel */
				 "event 442", 1, /* "you're not on that channel" */
				 "event 479", 1, /* "Cannot join channel (illegal name)" IMHO this is not a logical reply from server. */
				 NULL);

	/* MODE #channel b */
	server_redirect_register("mode b", FALSE, 0,
                                 "event 367", 1,
				 NULL,
				 "event 368", 1, /* End of Channel ban List */
				 "event 403", 1, /* no such channel */
				 "event 442", 1, /* "you're not on that channel" */
				 "event 479", 1, /* "Cannot join channel (illegal name)" IMHO this is not a logical reply from server. */
				 NULL);

	/* MODE #channel e */
	server_redirect_register("mode e", FALSE, 0,
                                 "event 348", 1,
				 NULL,
				 "event 349", 1, /* End of ban exceptions */
				 "event 482", 1, /* not channel operator - OPN's ircd doesn't want non-ops to see ban exceptions */
				 "event 403", 1, /* no such channel */
				 "event 442", 1, /* "you're not on that channel" */
				 "event 479", 1, /* "Cannot join channel (illegal name)" IMHO this is not a logical reply from server. */
				 "event 472", -1, /* unknown mode (you should check e-mode's existance from 004 event instead of relying on this) */
				 NULL);

	/* MODE #channel I */
	server_redirect_register("mode e", FALSE, 0,
                                 "event 346", 1,
				 NULL,
				 "event 347", 1, /* End of invite list */
				 "event 403", 1, /* no such channel */
				 "event 442", 1, /* "you're not on that channel" */
				 "event 479", 1, /* "Cannot join channel (illegal name)" IMHO this is not a logical reply from server. */
				 "event 472", -1, /* unknown mode (you should check I-mode's existance from 004 event instead of relying on this) */
				 NULL);

        /* PING */
	server_redirect_register("ping", TRUE, 60,
				 NULL,
                                 "event 402", -1, /* no such server */
				 "event pong", -1, /* PONG */
				 NULL);

	signal_add("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}

void servers_redirect_deinit(void)
{
	g_hash_table_foreach(command_redirects,
			     (GHFunc) cmd_redirect_destroy, NULL);
        g_hash_table_destroy(command_redirects);

	signal_remove("server disconnected", (SIGNAL_FUNC) sig_disconnected);
}
