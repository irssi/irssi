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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/signals.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/rawlog.h>

#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/irc/core/servers-redirect.h>

#define DEFAULT_REDIRECT_TIMEOUT 60

/* Allow one non-expected redirections to come before the expected one
   before aborting it. Some IRC bouncers/proxies reply to eg. PINGs
   immediately. */
#define MAX_FAILURE_COUNT 1

typedef struct {
        char *name;
	int refcount;

	int remote;
	int timeout;
	int pos;
	GSList *start, *stop, *opt; /* char *event, int argpos, ... */
} REDIRECT_CMD_REC;

struct _REDIRECT_REC {
	REDIRECT_CMD_REC *cmd;
	time_t created;
	int failures;
	char *prefix;

	unsigned int destroyed:1;
	unsigned int aborted:1;
	unsigned int remote:1;
	unsigned int first_signal_sent:1;

	char *arg;
        int count;
	char *failure_signal, *default_signal, *first_signal, *last_signal;
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
	for (tmp = rec->opt; tmp != NULL; tmp = tmp->next->next)
                g_free(tmp->data);
        g_slist_free(rec->start);
        g_slist_free(rec->stop);
        g_slist_free(rec->opt);
        g_free(rec->name);
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

	g_free_not_null(rec->prefix);
	g_free_not_null(rec->arg);
        g_free_not_null(rec->failure_signal);
        g_free_not_null(rec->default_signal);
        g_free_not_null(rec->first_signal);
        g_free_not_null(rec->last_signal);
	g_slist_foreach(rec->signals, (GFunc) g_free, NULL);
	g_slist_free(rec->signals);
        g_free(rec);
}

void server_redirect_register(const char *command,
			      int remote, int timeout, ...)
{
	va_list va;
	GSList *start, *stop, *opt, **list;
	const char *event;
        int argpos;

	va_start(va, timeout);
	start = stop = opt = NULL; list = &start;
	for (;;) {
		event = va_arg(va, const char *);
		if (event == NULL) {
			if (list == &start)
				list = &stop;
			else if (list == &stop)
				list = &opt;
			else
                                break;
                        continue;
		}

                argpos = va_arg(va, int);
		*list = g_slist_append(*list, g_strdup(event));
		*list = g_slist_append(*list, GINT_TO_POINTER(argpos));
	}

	va_end(va);

	server_redirect_register_list(command, remote, timeout, start, stop, opt, 0);
}

void server_redirect_register_list(const char *command, int remote, int timeout, GSList *start,
                                   GSList *stop, GSList *opt, int pos)
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
	}

	rec = g_new0(REDIRECT_CMD_REC, 1);
        redirect_cmd_ref(rec);
        rec->name = g_strdup(command);
	rec->remote = remote;
	rec->timeout = timeout > 0 ? timeout : DEFAULT_REDIRECT_TIMEOUT;
	rec->start = start;
        rec->stop = stop;
        rec->opt = opt;
	rec->pos = pos;
	g_hash_table_insert(command_redirects, rec->name, rec);
}

void server_redirect_event(IRC_SERVER_REC *server, const char *command,
			   int count, const char *arg, int remote,
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

	server_redirect_event_list(server, command, count, arg, remote,
				   failure_signal, signals);
}

/* Find specified event from signals list. If it's found, remove it from the
   list and return it's target signal. */
static char *signal_list_move(GSList **signals, const char *event)
{
	GSList *link;
        char *linkevent, *linksignal;

	link = i_slist_find_string(*signals, event);
	if (link == NULL)
		return NULL;

	linkevent = link->data;
        linksignal = link->next->data;

	*signals = g_slist_remove(*signals, linkevent);
	*signals = g_slist_remove(*signals, linksignal);

	g_free(linkevent);
        return linksignal;
}

void server_redirect_event_list(IRC_SERVER_REC *server, const char *command,
				int count, const char *arg, int remote,
				const char *failure_signal, GSList *signals)
{
	REDIRECT_CMD_REC *cmdrec;
	REDIRECT_REC *rec;

	g_return_if_fail(IS_IRC_SERVER(server));
	g_return_if_fail(command != NULL);
        g_return_if_fail((g_slist_length(signals) & 1) == 0);

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
        rec->count = count;
	rec->remote = remote != -1 ? remote : cmdrec->remote;
	rec->failure_signal = g_strdup(failure_signal);

        rec->default_signal = signal_list_move(&signals, "");
        rec->first_signal = signal_list_move(&signals, "redirect first");
        rec->last_signal = signal_list_move(&signals, "redirect last");
	rec->signals = signals;

	if (server->redirect_next != NULL)
                server_redirect_destroy(server->redirect_next);
        server->redirect_next = rec;
}

void server_redirect_command(IRC_SERVER_REC *server, const char *command,
			     REDIRECT_REC *redirect)
{
        REDIRECT_CMD_REC *cmdrec;

	g_return_if_fail(IS_IRC_SERVER(server));
	g_return_if_fail(command != NULL);

	if (redirect == NULL) {
		/* no redirection wanted, but still register the command
		   so future redirections wont get messed up. */
		cmdrec = redirect_cmd_find(command);
		if (cmdrec == NULL)
			return;

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
			if (i_toupper(*arg) != i_toupper(*event_args))
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

		if (g_strcmp0(str, event) == 0)
                        break;
                list = list->next->next;
	}

        return list;
}

#define MATCH_NONE      0
#define MATCH_START	1
#define MATCH_STOP	2

static const char *redirect_match(REDIRECT_REC *redirect, const char *event,
				  const char *args, int *match)
{
	GSList *tmp, *cmdpos;
	const char *signal;
        int match_list;

	if (redirect->aborted)
                return NULL;

	/* get the signal for redirection event - if it's not found we'll
	   use the default signal */
        signal = NULL;
	for (tmp = redirect->signals; tmp != NULL; tmp = tmp->next->next) {
		if (g_strcmp0(tmp->data, event) == 0) {
			signal = tmp->next->data;
			break;
		}
	}

	/* find the argument position */
	if (redirect->destroyed) {
		/* stop event is already found for this redirection, but
		   we'll still want to look for optional events */
		cmdpos = redirect_cmd_list_find(redirect->cmd->opt, event);
		if (cmdpos == NULL)
			return NULL;

                match_list = MATCH_STOP;
	} else {
                /* look from start/stop lists */
		cmdpos = redirect_cmd_list_find(redirect->cmd->start, event);
		if (cmdpos != NULL)
			match_list = MATCH_START;
		else {
			cmdpos = redirect_cmd_list_find(redirect->cmd->stop,
							event);
			if (cmdpos != NULL)
				match_list = MATCH_STOP;
			else if (redirect->default_signal != NULL &&
					args == NULL &&
					strncmp(event, "event ", 6) == 0 &&
					i_isdigit(event[6])) {
				/* If there is a default signal, the
				 * redirection has already started and
				 * this is a numeric, use it */
				/* XXX this should depend on the
				 * REDIRECT_CMD_REC, not REDIRECT_REC */
				if (signal == NULL)
					signal = redirect->default_signal;
				match_list = MATCH_START;
			} else {
				match_list = MATCH_NONE;
			}
		}
	}

	if (signal == NULL && cmdpos == NULL) {
		/* event not found from specified redirection events nor
		   registered command events, and no default signal */
		return NULL;
	}

	/* check that arguments match */
	if (args != NULL && redirect->arg != NULL && cmdpos != NULL &&
	    !redirect_args_match(args, redirect->arg,
				 GPOINTER_TO_INT(cmdpos->next->data)))
		return NULL;

        *match = match_list;
	return signal != NULL ? signal : redirect->default_signal;
}

static void redirect_abort(IRC_SERVER_REC *server, REDIRECT_REC *rec)
{
	char *str;

	server->redirects =
		g_slist_remove(server->redirects, rec);

	if (rec->aborted || !rec->destroyed) {
		/* emit the failure signal */
		if (rec->failure_signal != NULL)
			str = g_strdup_printf("FAILED %s: %s", rec->cmd->name, rec->failure_signal);
		else
			str = g_strdup_printf("FAILED %s", rec->cmd->name);

		rawlog_redirect(server->rawlog, str);
		g_free(str);

		if (rec->failure_signal != NULL)
			signal_emit(rec->failure_signal, 3, server, rec->cmd->name, rec->arg);
	} else if (rec->last_signal != NULL) {
                /* emit the last signal */
		signal_emit(rec->last_signal, 1, server);
	}

	server->redirect_active = g_slist_remove(server->redirect_active, rec);

	server_redirect_destroy(rec);
}

#define REDIRECT_IS_TIMEOUTED(rec) \
	((now-(rec)->created) > (rec)->cmd->timeout)


static REDIRECT_REC *redirect_find(IRC_SERVER_REC *server, const char *event,
				   const char *args, const char **signal,
				   int *match)
{
        REDIRECT_REC *redirect;
	GSList *tmp, *next;
	time_t now;
        const char *match_signal;

	/* find the redirection */
	*signal = NULL; redirect = NULL;
	for (tmp = server->redirects; tmp != NULL; tmp = tmp->next) {
		REDIRECT_REC *rec = tmp->data;

		/* already active, don't try to start it again */
		if (g_slist_find(server->redirect_active, rec) != NULL)
			continue;

		match_signal = redirect_match(rec, event, args, match);
		if (match_signal != NULL && *match != MATCH_NONE) {
			redirect = rec;
                        *signal = match_signal;
			break;
		}
	}

	if (g_strcmp0("event 263", event) == 0) { /* RPL_TRYAGAIN */
		char *params, *command;
		params = event_get_params(args, 3, NULL, &command, NULL);

		for (tmp = server->redirects; tmp != NULL; tmp = next) {
			REDIRECT_REC *rec = tmp->data;

			next = tmp->next;

			if (rec == redirect)
				break;

			if (g_slist_find(server->redirect_active, rec) != NULL)
				continue;

			if (redirect_args_match(rec->cmd->name, command, rec->cmd->pos)) {
				/* the server crashed our command with RPL_TRYAGAIN, send the
				   failure */
				rec->aborted = TRUE;
				redirect_abort(server, rec);
				break;
			}
		}
		g_free(params);
	}

	/* remove the destroyed, non-remote and timeouted remote
	   redirections that should have happened before this redirection */
	now = time(NULL);
	for (tmp = server->redirects; tmp != NULL; tmp = next) {
		REDIRECT_REC *rec = tmp->data;

		if (rec == redirect)
			break;

		next = tmp->next;
		if (rec->destroyed) {
                        /* redirection is finished, destroy it */
			redirect_abort(server, rec);
		} else if (redirect != NULL) {
                        /* check if redirection failed */
			if (rec->aborted ||
			    rec->failures++ >= MAX_FAILURE_COUNT) {
                                /* enough failures, abort it now */
				if (!rec->remote || REDIRECT_IS_TIMEOUTED(rec))
					redirect_abort(server, rec);
			}
		}
	}

        return redirect;
}

static const char *
server_redirect_get(IRC_SERVER_REC *server, const char *prefix,
		    const char *event, const char *args,
		    REDIRECT_REC **redirect, int *match)
{
	const char *signal = NULL;
	GSList *ptr, *next;
	REDIRECT_REC *r;

        *redirect = NULL;
	*match = MATCH_NONE;

	if (server->redirects == NULL)
		return NULL;

	for (ptr = server->redirect_active; ptr != NULL; ptr = next) {
		next = ptr->next;
		r = ptr->data;
		if (prefix != NULL && r->prefix != NULL &&
				g_strcmp0(prefix, r->prefix)) {
			/* not from this server */
			continue;
		}
		/* redirection is already started, now we'll just need to
		   keep redirecting until stop-event is found. */
		*redirect = r;
		signal = redirect_match(*redirect, event, NULL, match);
		if (signal == NULL) {
			/* not a numeric, so we've lost the
			   stop event.. */
			(*redirect)->aborted = TRUE;
			redirect_abort(server, *redirect);

			*redirect = NULL;
		}
		if (*redirect != NULL)
			break;
	}

	if (*redirect == NULL) {
                /* find the redirection */
		*redirect = redirect_find(server, event, args, &signal, match);
	}

	/* remember which server is replying to our request */
	if (*redirect != NULL && prefix != NULL && (*redirect)->prefix == NULL)
		(*redirect)->prefix = g_strdup(prefix);

	if (*redirect != NULL && (*redirect)->first_signal != NULL &&
	    !(*redirect)->first_signal_sent) {
		/* emit the first_signal */
                (*redirect)->first_signal_sent = TRUE;
		signal_emit((*redirect)->first_signal, 1, server);
	}

        return signal;
}

const char *server_redirect_get_signal(IRC_SERVER_REC *server,
				       const char *prefix,
				       const char *event,
				       const char *args)
{
	REDIRECT_REC *redirect;
        const char *signal;
	int match;

	signal = server_redirect_get(server, prefix, event, args, &redirect, &match);
	if (redirect == NULL)
		;
	else if (match != MATCH_STOP) {
		if (g_slist_find(server->redirect_active, redirect) == NULL)
			server->redirect_active = g_slist_prepend(server->redirect_active, redirect);
	} else {
		/* stop event - remove this redirection next time this
		   function is called (can't destroy now or our return
		   value would be corrupted) */
                if (--redirect->count <= 0)
			redirect->destroyed = TRUE;
		server->redirect_active = g_slist_remove(server->redirect_active, redirect);
	}

        return signal;
}

const char *server_redirect_peek_signal(IRC_SERVER_REC *server,
					const char *prefix,
					const char *event,
					const char *args,
					int *redirected)
{
	REDIRECT_REC *redirect;
        const char *signal;
	int match;

	signal = server_redirect_get(server, prefix, event, args, &redirect, &match);
	*redirected = match != MATCH_NONE;
        return signal;
}

static void sig_disconnected(IRC_SERVER_REC *server)
{
	if (!IS_IRC_SERVER(server))
                return;

	g_slist_free(server->redirect_active);
        server->redirect_active = NULL;
	g_slist_foreach(server->redirects,
			(GFunc) server_redirect_destroy, NULL);
	g_slist_free(server->redirects);
        server->redirects = NULL;

	if (server->redirect_next != NULL) {
		server_redirect_destroy(server->redirect_next);
                server->redirect_next = NULL;
	}
}

static void cmd_redirect_destroy(char *key, REDIRECT_CMD_REC *cmd)
{
        redirect_cmd_unref(cmd);
}

void servers_redirect_init(void)
{
	command_redirects = g_hash_table_new((GHashFunc) g_str_hash, (GCompareFunc) g_str_equal);

	/* WHOIS - register as remote command by default
	   with a default timeout */
	server_redirect_register("whois", TRUE, 0,
				 "event 311", 1, /* Begins the WHOIS */
				 NULL,
                                 "event 401", 1, /* No such nick */
				 "event 318", 1, /* End of WHOIS */
                                 "event 402", 1, /* No such server */
                                 "event 431", 1, /* No nickname given */
                                 "event 461", 1, /* Not enough parameters */
				 NULL,
				 "event 318", 1, /* After 401, we should get 318, but in OPN we don't.. */
				 NULL);

	/* WHOWAS */
	server_redirect_register("whowas", FALSE, 0,
				 "event 314", 1, /* Begins the WHOWAS */
                                 "event 406", 1, /* There was no such nick */
				 NULL,
				 "event 369", 1, /* End of WHOWAS */
				 NULL,
				 NULL);

	/* WHO */
	server_redirect_register("who", FALSE, 0,
				 "event 352", 1, /* An element of the WHO */
				 "event 354", -1, /* WHOX element */
                                 "event 401", 1, /* No such nick/channel */
				 NULL,
				 "event 315", 1, /* End of WHO */
				 "event 403", 1, /* no such channel */
				 NULL,
				 NULL);

	/* WHO user */
	server_redirect_register("who user", FALSE, 0, /* */
	                         "event 352", 5,       /* An element of the WHO */
	                         "event 354", -1,      /* WHOX element */
	                         NULL,                 /* */
	                         "event 315", 1,       /* End of WHO */
	                         NULL,                 /* */
	                         NULL);

	/* LIST */
	server_redirect_register("list", FALSE, 0,
				 "event 321", 1, /* Begins the LIST */
				 NULL,
				 "event 323", 1, /* End of LIST */
				 NULL,
				 NULL);

        /* ISON */
	server_redirect_register("ison", FALSE, 0,
				 NULL,
				 "event 303", -1, /* ISON */
				 NULL,
				 NULL);

        /* USERHOST */
	server_redirect_register("userhost", FALSE, 0,
				 "event 401", 1, /* no such nick */
				 NULL,
				 "event 302", -1, /* Userhost */
				 "event 461", -1, /* Not enough parameters */
				 NULL,
				 NULL);

	/* MODE user */
	server_redirect_register("mode user", FALSE, 0,
				 NULL,
				 "event mode", 0, /* MODE-reply */
				 "event 501", -1, /* Uknown MODE flag */
				 "event 502", -1, /* Can't change mode for other users */
				 "event 403", 1, /* That channel doesn't exist (tried to change mode to others) */
				 NULL,
				 NULL);

	/* MODE #channel */
	server_redirect_register("mode channel", FALSE, 0,
				 NULL,
				 "event 324", 1, /* MODE-reply */
				 "event 403", 1, /* no such channel */
				 "event 442", 1, /* "you're not on that channel" */
				 "event 479", 1, /* "Cannot join channel (illegal name)" IMHO this is not a logical reply from server. */
				 NULL,
                                 "event 329", 1, /* Channel create time */
				 NULL);

	/* MODE #channel b */
	server_redirect_register("mode b", FALSE, 0,
                                 "event 367", 1,
				 NULL,
				 "event 368", 1, /* End of Channel ban List */
				 "event 403", 1, /* no such channel */
				 "event 442", 1, /* "you're not on that channel" */
				 "event 479", 1, /* "Cannot join channel (illegal name)" IMHO this is not a logical reply from server. */
				 NULL,
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
				 "event 472", -1, /* unknown mode (you should check e-mode's existence from 004 event instead of relying on this) */
				 NULL,
				 NULL);

	/* MODE #channel I */
	server_redirect_register("mode I", FALSE, 0,
                                 "event 346", 1,
				 NULL,
				 "event 347", 1, /* End of invite list */
				 "event 482", 1, /* not channel operator - OPN's ircd doesn't want non-ops to see ban exceptions */
				 "event 403", 1, /* no such channel */
				 "event 442", 1, /* "you're not on that channel" */
				 "event 479", 1, /* "Cannot join channel (illegal name)" IMHO this is not a logical reply from server. */
				 "event 472", -1, /* unknown mode (you should check I-mode's existence from 004 event instead of relying on this) */
				 NULL,
				 NULL);

        /* PING - use default timeout */
	server_redirect_register("ping", TRUE, 0,
				 NULL,
                                 "event 402", -1, /* no such server */
				 "event pong", -1, /* PONG */
				 NULL,
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
