/*
 fe-exec.c : irssi

    Copyright (C) 2000-2001 Timo Sirainen

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
#include <irssi/src/core/modules.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/pidwait.h>
#include <irssi/src/core/line-split.h>
#include <irssi/src/core/network.h>
#include <irssi/src/core/net-sendbuffer.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/levels.h>

#include <irssi/src/core/servers.h>
#include <irssi/src/core/channels.h>
#include <irssi/src/core/queries.h>

#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-common/core/fe-exec.h>
#include <irssi/src/fe-common/core/fe-windows.h>
#include <irssi/src/fe-common/core/window-items.h>

#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

GSList *processes;
static int signal_exec_input;

static void exec_wi_destroy(EXEC_WI_REC *rec)
{
        g_return_if_fail(rec != NULL);

	if (rec->destroying) return;
	rec->destroying = TRUE;

	rec->process->target_item = NULL;
	if (window_item_window((WI_ITEM_REC *) rec) != NULL)
		window_item_destroy((WI_ITEM_REC *) rec);

	MODULE_DATA_DEINIT(rec);
	g_free(rec->visible_name);
        g_free(rec);
}

static const char *exec_get_target(WI_ITEM_REC *item)
{
	return ((EXEC_WI_REC *) item)->visible_name;
}

static EXEC_WI_REC *exec_wi_create(WINDOW_REC *window, PROCESS_REC *rec)
{
	EXEC_WI_REC *item;

        g_return_val_if_fail(window != NULL, NULL);
        g_return_val_if_fail(rec != NULL, NULL);

	item = g_new0(EXEC_WI_REC, 1);
	item->type = module_get_uniq_id_str("WINDOW ITEM TYPE", "EXEC");
        item->destroy = (void (*) (WI_ITEM_REC *)) exec_wi_destroy;
	item->get_target = exec_get_target;
	item->visible_name = rec->name != NULL ? g_strdup(rec->name) :
		g_strdup_printf("%%%d", rec->id);

	item->createtime = time(NULL);
        item->process = rec;

	MODULE_DATA_INIT(item);
	window_item_add(window, (WI_ITEM_REC *) item, FALSE);
        return item;
}

static int process_get_new_id(void)
{
        PROCESS_REC *rec;
	GSList *tmp;
	int id;

	id = 0;
	tmp = processes;
	while (tmp != NULL) {
		rec = tmp->data;

		if (id != rec->id) {
			tmp = tmp->next;
			continue;
		}

		id++;
		tmp = processes;
	}

	return id;
}

static PROCESS_REC *process_find_pid(int pid)
{
	GSList *tmp;

        g_return_val_if_fail(pid > 0, NULL);

	for (tmp = processes; tmp != NULL; tmp = tmp->next) {
		PROCESS_REC *rec = tmp->data;

		if (rec->pid == pid)
			return rec;
	}

	return NULL;
}

static PROCESS_REC *process_find_id(int id, int verbose)
{
	GSList *tmp;

        g_return_val_if_fail(id != -1, NULL);

	for (tmp = processes; tmp != NULL; tmp = tmp->next) {
		PROCESS_REC *rec = tmp->data;

		if (rec->id == id)
			return rec;
	}

	if (verbose) {
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
			  "Unknown process id: %d", id);
	}

	return NULL;
}

static PROCESS_REC *process_find(const char *name, int verbose)
{
	GSList *tmp;

        g_return_val_if_fail(name != NULL, NULL);

	if (*name == '%' && is_numeric(name+1, 0))
                return process_find_id(atoi(name+1), verbose);

	for (tmp = processes; tmp != NULL; tmp = tmp->next) {
		PROCESS_REC *rec = tmp->data;

		if (rec->name != NULL && g_strcmp0(rec->name, name) == 0)
			return rec;
	}

	if (verbose) {
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
			  "Unknown process name: %s", name);
	}

	return NULL;
}

static void process_destroy(PROCESS_REC *rec, int status)
{
	processes = g_slist_remove(processes, rec);

	signal_emit("exec remove", 2, rec, GINT_TO_POINTER(status));

	if (rec->read_tag != -1)
		g_source_remove(rec->read_tag);
	if (rec->target_item != NULL)
                exec_wi_destroy(rec->target_item);

	line_split_free(rec->databuf);
        g_io_channel_shutdown(rec->in, TRUE, NULL);
        g_io_channel_unref(rec->in);
        net_sendbuffer_destroy(rec->out, TRUE);

	g_free_not_null(rec->name);
	g_free_not_null(rec->target);
	g_free_not_null(rec->target_server);
        g_free(rec->args);
        g_free(rec);
}

static void processes_killall(int signum)
{
	GSList *tmp;
	int kill_ret;

	for (tmp = processes; tmp != NULL; tmp = tmp->next) {
		PROCESS_REC *rec = tmp->data;

		kill_ret = kill(-rec->pid, signum);
		if (kill_ret != 0)
		        printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
		                  "Error sending signal %d to pid %d: %s",
		                  signum, rec->pid, g_strerror(errno));
	}
}

static int signal_name_to_id(const char *name)
{
	/* check only the few most common signals, too much job to check
	   them all. if we sometimes want more, procps-sources/proc/sig.c
	   would be useful for copypasting */
	if (g_ascii_strcasecmp(name, "hup") == 0)
                return SIGHUP;
	if (g_ascii_strcasecmp(name, "int") == 0)
                return SIGINT;
	if (g_ascii_strcasecmp(name, "term") == 0)
                return SIGTERM;
	if (g_ascii_strcasecmp(name, "kill") == 0)
                return SIGKILL;
	if (g_ascii_strcasecmp(name, "usr1") == 0)
                return SIGUSR1;
	if (g_ascii_strcasecmp(name, "usr2") == 0)
                return SIGUSR2;
        return -1;
}

/* `optlist' should contain only one unknown key - the server tag.
   returns NULL if there was unknown -option */
static int cmd_options_get_signal(const char *cmd,
				  GHashTable *optlist)
{
	GList *list;
	char *signame;
        int signum;

	/* get all the options, then remove the known ones. there should
	   be only one left - the signal */
	list = optlist_remove_known(cmd, optlist);

	if (list == NULL)
		return -1;

	signame = list->data;
	signum = -1;

	signum = is_numeric(signame, 0) ? atol(signame) :
		signal_name_to_id(signame);

	if (signum == -1 || list->next != NULL) {
		/* unknown option (not a signal) */
		signal_emit("error command", 2,
			    GINT_TO_POINTER(CMDERR_OPTION_UNKNOWN),
			    signum == -1 ? list->data : list->next->data);
		signal_stop();
                return -2;
	}

	g_list_free(list);
	return signum;
}

static void exec_show_list(void)
{
	GSList *tmp;

	for (tmp = processes; tmp != NULL; tmp = tmp->next) {
		PROCESS_REC *rec = tmp->data;

		printtext(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			  "%d (%s): %s", rec->id, rec->name, rec->args);
	}
}

static void process_exec(PROCESS_REC *rec, const char *cmd)
{
	const char *shell_args[4] = { FHS_PREFIX "/bin/sh", "-c", NULL, NULL };
	char **args;
	int in[2], out[2];
        int n;

	if (pipe(in) == -1)
                return;
	if (pipe(out) == -1)
		return;

	shell_args[2] = cmd;
	rec->pid = fork();
	if (rec->pid == -1) {
                /* error */
		close(in[0]); close(in[1]);
                close(out[0]); close(out[1]);
		return;
	}

	if (rec->pid != 0) {
		/* parent process */
		GIOChannel *outio = i_io_channel_new(in[1]);

		rec->in = i_io_channel_new(out[0]);
		rec->out = net_sendbuffer_create(outio, 0);

                close(out[1]);
		close(in[0]);
		pidwait_add(rec->pid);
                return;
	}

	/* child process, try to clean up everything */
	setsid();

#ifndef __ANDROID__
	if (setuid(getuid()) != 0)
		_exit(EXIT_FAILURE);

	if (setgid(getgid()) != 0)
		_exit(EXIT_FAILURE);
#endif

	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_DFL);

	putenv("TERM=tty");

	/* set stdin, stdout and stderr */
        dup2(in[0], STDIN_FILENO);
        dup2(out[1], STDOUT_FILENO);
	dup2(out[1], STDERR_FILENO);

        /* don't let child see our files */
	for (n = 3; n < 256; n++)
                close(n);

	if (rec->shell) {
		execvp(shell_args[0], (char **) shell_args);

		fprintf(stderr, "Exec: " FHS_PREFIX "/bin/sh: %s\n", g_strerror(errno));
	} else {
		args = g_strsplit(cmd, " ", -1);
                execvp(args[0], args);

		fprintf(stderr, "Exec: %s: %s\n", args[0], g_strerror(errno));
	}

	_exit(-1);
}

static void sig_exec_input_reader(PROCESS_REC *rec)
{
        char tmpbuf[512], *str;
        int recvlen;
	int ret;

	g_return_if_fail(rec != NULL);

	recvlen = net_receive(rec->in, tmpbuf, sizeof(tmpbuf));
	do {
		ret = line_split(tmpbuf, recvlen, &str, &rec->databuf);
		if (ret == -1) {
			/* link to terminal closed? */
			g_source_remove(rec->read_tag);
                        rec->read_tag = -1;
			break;
		}

		if (ret > 0) {
			signal_emit_id(signal_exec_input, 2, rec, str);
                        if (recvlen > 0) recvlen = 0;
		}
	} while (ret > 0);
}

static void handle_exec(const char *args, GHashTable *optlist,
                        SERVER_REC *server, WI_ITEM_REC *item)
{
	PROCESS_REC *rec;
	SERVER_REC *target_server;
        char *target, *level;
	int notice, signum, interactive, target_nick, target_channel, kill_ret;

	/* check that there's no unknown options. we allowed them
	   because signals can be used as options, but there should be
	   only one unknown option: the signal name/number. */
	signum = cmd_options_get_signal("exec", optlist);
	if (signum == -2)
                return;

	if (*args == '\0') {
		exec_show_list();
                return;
	}

	target = NULL;
	target_server = NULL;
	notice = FALSE;

	if (g_hash_table_lookup(optlist, "in") != NULL) {
		rec = process_find(g_hash_table_lookup(optlist, "in"), TRUE);
		if (rec != NULL) {
			net_sendbuffer_send(rec->out, args, strlen(args));
			net_sendbuffer_send(rec->out, "\n", 1);
		}
		return;
	}

	/* check if args is a process ID or name. if it's ID but not found,
	   complain about it and fail immediately */
	rec = process_find(args, *args == '%');
	if (*args == '%' && rec == NULL)
		return;

        /* common options */
        target_channel = target_nick = FALSE;
	if (g_hash_table_lookup(optlist, "out") != NULL) {
                /* redirect output to active channel/query */
		if (item == NULL)
			cmd_return_error(CMDERR_NOT_JOINED);
		target = (char *) window_item_get_target(item);
		target_server = item->server;
		target_channel = IS_CHANNEL(item);
		target_nick = IS_QUERY(item);
	} else if (g_hash_table_lookup(optlist, "msg") != NULL) {
                /* redirect output to /msg <nick> */
		target = g_hash_table_lookup(optlist, "msg");
		target_server = server;
	} else if (g_hash_table_lookup(optlist, "notice") != NULL) {
		target = g_hash_table_lookup(optlist, "notice");
		target_server = server;
                notice = TRUE;
	}

        /* options that require process ID/name as argument */
	if (rec == NULL &&
	    (signum != -1 || g_hash_table_lookup(optlist, "close") != NULL)) {
		printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
			  "Unknown process name: %s", args);
		return;
	}
	if (g_hash_table_lookup(optlist, "close") != NULL) {
		/* forcibly close the process */
                process_destroy(rec, -1);
                return;
	}

	if (signum != -1) {
		/* send a signal to process group */
                kill_ret = kill(-rec->pid, signum);
                if (kill_ret != 0)
                        printtext(NULL, NULL, MSGLEVEL_CLIENTERROR,
                                  "Error sending signal %d to pid %d: %s",
                                  signum, rec->pid, g_strerror(errno));
                return;
	}

        interactive = g_hash_table_lookup(optlist, "interactive") != NULL;
	if (*args == '%') {
		/* do something to already existing process */
		char *name;

		if (target != NULL) {
                        /* redirect output to target */
			g_free_and_null(rec->target);
			rec->target = g_strdup(target);
			rec->target_server = target_server == NULL ? NULL :
				g_strdup(target_server->tag);
                        rec->notice = notice;
		}

                name = g_hash_table_lookup(optlist, "name");
		if (name != NULL) {
			/* change window name */
			g_free_not_null(rec->name);
			rec->name = *name == '\0' ? NULL : g_strdup(name);
		} else if (target == NULL &&
			   (rec->target_item == NULL || interactive)) {
			/* no parameters given,
			   redirect output to the active window */
			g_free_and_null(rec->target);
			rec->target_win = active_win;

			if (rec->target_item != NULL)
				exec_wi_destroy(rec->target_item);

			if (interactive) {
				rec->target_item =
					exec_wi_create(active_win, rec);
			}
		}
                return;
	}

        /* starting a new process */
	rec = g_new0(PROCESS_REC, 1);
	rec->pid = -1;
        rec->shell = g_hash_table_lookup(optlist, "nosh") == NULL;

	process_exec(rec, args);
	if (rec->pid == -1) {
                /* pipe() or fork() failed */
		g_free(rec);
		cmd_return_error(CMDERR_ERRNO);
	}

        rec->id = process_get_new_id();
	rec->target = g_strdup(target);
	rec->target_server = target_server == NULL ? NULL :
		g_strdup(target_server->tag);
	rec->target_win = active_win;
	rec->target_channel = target_channel;
	rec->target_nick = target_nick;
        rec->args = g_strdup(args);
	rec->notice = notice;
        rec->silent = g_hash_table_lookup(optlist, "-") != NULL;
        rec->quiet = g_hash_table_lookup(optlist, "quiet") != NULL;
	rec->name = g_strdup(g_hash_table_lookup(optlist, "name"));

	level = g_hash_table_lookup(optlist, "level");
	rec->level = level == NULL ? MSGLEVEL_CLIENTCRAP : level2bits(level, NULL);

	rec->read_tag =
	    i_input_add(rec->in, I_INPUT_READ, (GInputFunction) sig_exec_input_reader, rec);
	processes = g_slist_append(processes, rec);

	if (rec->target == NULL && interactive)
		rec->target_item = exec_wi_create(active_win, rec);

	signal_emit("exec new", 1, rec);
}

/* SYNTAX: EXEC [-] [-nosh] [-out | -msg <target> | -notice <target>]
		[-name <name>] <cmd line>
	   EXEC -out | -window | -msg <target> | -notice <target> |
		-close | -<signal> %<id>
	   EXEC -in %<id> <text to send to process> */
static void cmd_exec(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	GHashTable *optlist;
        char *args;
	void *free_arg;

	g_return_if_fail(data != NULL);

	if (cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS |
			   PARAM_FLAG_UNKNOWN_OPTIONS | PARAM_FLAG_GETREST,
			   "exec", &optlist, &args)) {
		handle_exec(args, optlist, server, item);
		cmd_params_free(free_arg);
	}
}

static void sig_pidwait(void *pid, void *statusp)
{
	PROCESS_REC *rec;
        char *str;
	int status = GPOINTER_TO_INT(statusp);

        rec = process_find_pid(GPOINTER_TO_INT(pid));
	if (rec == NULL) return;

	/* process exited - print the last line if
	   there wasn't a newline at end. */
	if (line_split("\n", 1, &str, &rec->databuf) > 0 && *str != '\0')
		signal_emit_id(signal_exec_input, 2, rec, str);

	if (!rec->silent) {
		if (WIFSIGNALED(status)) {
			status = WTERMSIG(status);
			printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
				  "process %d (%s) terminated with signal %d (%s)",
				  rec->id, rec->args,
				  status, g_strsignal(status));
		} else {
                        status = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
			printtext(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
				  "process %d (%s) terminated with return code %d",
				  rec->id, rec->args, status);
		}
	}
	process_destroy(rec, status);
}

static void sig_exec_input(PROCESS_REC *rec, const char *text)
{
	WI_ITEM_REC *item;
	SERVER_REC *server;
        char *str;

	if (rec->quiet)
		return;

        item = NULL;
	server = NULL;

	if (rec->target != NULL) {
		if (rec->target_server != NULL) {
			server = server_find_tag(rec->target_server);
			if (server == NULL) {
				/* disconnected - target is lost */
				return;
			}
			item = NULL;
		} else {
			item = window_item_find(NULL, rec->target);
			server = item != NULL ? item->server :
				active_win->active_server;
		}

		str = g_strconcat(rec->target_nick ? "-nick " :
				  rec->target_channel ? "-channel " : "",
				  rec->target, " ", *text == '\0' ? " " : text, NULL);
		signal_emit(rec->notice ? "command notice" : "command msg",
			    3, str, server, item);
                g_free(str);
	} else if (rec->target_item != NULL) {
		printtext(NULL, rec->target_item->visible_name,
			  rec->level, "%s", text);
	} else {
		printtext_window(rec->target_win, rec->level, "%s", text);
	}
}

static void sig_window_destroyed(WINDOW_REC *window)
{
	GSList *tmp;

	/* window is being closed, if there's any /exec targets for it,
	   change them to active window. */
	for (tmp = processes; tmp != NULL; tmp = tmp->next) {
		PROCESS_REC *rec = tmp->data;

		if (rec->target_win == window)
			rec->target_win = active_win;
	}
}

static void event_text(const char *data, SERVER_REC *server, EXEC_WI_REC *item)
{
	if (!IS_EXEC_WI(item))
		return;

	net_sendbuffer_send(item->process->out, data, strlen(data));
	net_sendbuffer_send(item->process->out, "\n", 1);
        signal_stop();
}

void fe_exec_init(void)
{
	command_bind("exec", NULL, (SIGNAL_FUNC) cmd_exec);
	command_set_options("exec", "!- interactive nosh +name out +msg +notice +in window close +level quiet");

        signal_exec_input = signal_get_uniq_id("exec input");
        signal_add("pidwait", (SIGNAL_FUNC) sig_pidwait);
        signal_add("exec input", (SIGNAL_FUNC) sig_exec_input);
        signal_add("window destroyed", (SIGNAL_FUNC) sig_window_destroyed);
	signal_add_first("send text", (SIGNAL_FUNC) event_text);
}

void fe_exec_deinit(void)
{
	if (processes != NULL) {
		processes_killall(SIGTERM);
		sleep(1);
		processes_killall(SIGKILL);

		while (processes != NULL)
			process_destroy(processes->data, -1);
	}

	command_unbind("exec", (SIGNAL_FUNC) cmd_exec);

        signal_remove("pidwait", (SIGNAL_FUNC) sig_pidwait);
        signal_remove("exec input", (SIGNAL_FUNC) sig_exec_input);
        signal_remove("window destroyed", (SIGNAL_FUNC) sig_window_destroyed);
	signal_remove("send text", (SIGNAL_FUNC) event_text);
}
