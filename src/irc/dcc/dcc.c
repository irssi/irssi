/*
 dcc.c : irssi

    Copyright (C) 1999 Timo Sirainen

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
#include "commands.h"
#include "network.h"
#include "line-split.h"
#include "settings.h"

#include "masks.h"
#include "irc.h"

#include "dcc.h"

void dcc_chat_init(void);
void dcc_chat_deinit(void);

void dcc_files_init(void);
void dcc_files_deinit(void);

#define DCC_TYPES 5

static gchar *dcc_types[] =
{
    "CHAT",
    "SEND",
    "GET",
    "RESUME",
    "ACCEPT"
};

GSList *dcc_conns;

static gint dcc_timeouttag;

/* Create new DCC record */
DCC_REC *dcc_create(gint type, gint handle, gchar *nick, gchar *arg, IRC_SERVER_REC *server, DCC_REC *chat)
{
    DCC_REC *dcc;

    g_return_val_if_fail(nick != NULL, NULL);
    g_return_val_if_fail(arg != NULL, NULL);

    dcc = g_new0(DCC_REC, 1);
    dcc->type = type == DCC_TYPE_CHAT ? module_get_uniq_id("IRC", WI_IRC_DCC_CHAT) : -1;
    dcc->mirc_ctcp = settings_get_bool("dcc_mirc_ctcp");
    dcc->created = time(NULL);
    dcc->chat = chat;
    dcc->dcc_type = type;
    dcc->arg = g_strdup(arg);
    dcc->nick = g_strdup(nick);
    dcc->handle = handle;
    dcc->fhandle = -1;
    dcc->tagread = dcc->tagwrite = -1;
    dcc->server = server;
    dcc->mynick = g_strdup(server != NULL ? server->nick :
        chat != NULL ? chat->nick : "??");
    dcc->ircnet = server == NULL ?
        chat == NULL || chat->ircnet == NULL ? NULL : g_strdup(chat->ircnet) :
        server->connrec->ircnet == NULL ? NULL : g_strdup(server->connrec->ircnet);
    dcc_conns = g_slist_append(dcc_conns, dcc);

    signal_emit("dcc created", 1, dcc);
    return dcc;
}

/* Destroy DCC record */
void dcc_destroy(DCC_REC *dcc)
{
    GSList *tmp;

    g_return_if_fail(dcc != NULL);

    dcc_conns = g_slist_remove(dcc_conns, dcc);

    /* remove dcc chat references.. */
    for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next)
    {
        DCC_REC *rec = tmp->data;

        if (rec->chat == dcc)
            rec->chat = NULL;
    }

    signal_emit("dcc destroyed", 1, dcc);

    if (dcc->fhandle != -1) close(dcc->fhandle);
    if (dcc->handle != -1) net_disconnect(dcc->handle);
    if (dcc->tagread != -1) g_source_remove(dcc->tagread);
    if (dcc->tagwrite != -1) g_source_remove(dcc->tagwrite);

    if (dcc->dcc_type == DCC_TYPE_CHAT)
        line_split_free((LINEBUF_REC *) dcc->databuf);
    else if (dcc->databuf != NULL) g_free(dcc->databuf);
    if (dcc->file != NULL) g_free(dcc->file);
    if (dcc->ircnet != NULL) g_free(dcc->ircnet);
    g_free(dcc->mynick);
    g_free(dcc->nick);
    g_free(dcc->arg);
    g_free(dcc);
}

gchar *dcc_make_address(IPADDR *ip)
{
    static gchar str[MAX_IP_LEN];
    gulong addr;

    if (is_ipv6_addr(ip))
    {
	/* IPv6 */
	net_ip2host(ip, str);
    }
    else
    {
	memcpy(&addr, &ip->addr, 4);
	sprintf(str, "%lu", (unsigned long) htonl(addr));
    }

    return str;
}

/* Find DCC record, arg can be NULL */
DCC_REC *dcc_find_item(gint type, gchar *nick, gchar *arg)
{
    DCC_REC *dcc;
    GSList *tmp;

    g_return_val_if_fail(nick != NULL, NULL);

    for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next)
    {
        dcc = tmp->data;

        if (dcc->dcc_type == type && g_strcasecmp(dcc->nick, nick) == 0 &&
           (arg == NULL || strcmp(dcc->arg, arg) == 0))
            return dcc;
    }

    return NULL;
}

/* Find DCC record by port # */
DCC_REC *dcc_find_by_port(gchar *nick, gint port)
{
    DCC_REC *dcc;
    GSList *tmp;

    for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next)
    {
        dcc = tmp->data;

        if (dcc->port == port && ((dcc->dcc_type == DCC_TYPE_GET || dcc->dcc_type == DCC_TYPE_SEND) && g_strcasecmp(dcc->nick, nick) == 0))
        {
            /* found! */
            return dcc;
        }
    }

    return NULL;
}

gchar *dcc_type2str(gint type)
{
    g_return_val_if_fail(type >= 1 && type <= DCC_TYPES, NULL);
    return dcc_types[type-1];
}

gint dcc_str2type(gchar *type)
{
    gint num;

    for (num = 0; num < DCC_TYPES; num++)
        if (g_strcasecmp(dcc_types[num], type) == 0) return num+1;

    return 0;
}

void dcc_ctcp_message(gchar *target, IRC_SERVER_REC *server, DCC_REC *chat, gboolean notice, gchar *msg)
{
    gchar *str;

    if (chat != NULL)
    {
        /* send it via open DCC chat */
	/* FIXME: we need output queue! */
        str = g_strdup_printf("%s\001%s\001\n", chat->mirc_ctcp ? "" :
                              notice ? "CTCP_REPLY " : "CTCP_MESSAGE ", msg);
        net_transmit(chat->handle, str, strlen(str));
    }
    else
    {
        str = g_strdup_printf("%s %s :\001%s\001",
                              notice ? "NOTICE" : "PRIVMSG", target, msg);
        irc_send_cmd(server, str);
    }

    g_free(str);
}

/* Server connected, check if there's any open dcc sessions for this ircnet.. */
static void dcc_server_connected(IRC_SERVER_REC *server)
{
	GSList *tmp;

	g_return_if_fail(server != NULL);

	if (server->connrec->ircnet == NULL)
		return;

	for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next) {
		DCC_REC *dcc = tmp->data;

		if (dcc->server == NULL && dcc->ircnet != NULL &&
		    g_strcasecmp(dcc->ircnet, server->connrec->ircnet) == 0) {
			dcc->server = server;
			g_free(dcc->mynick);
			dcc->mynick = g_strdup(server->nick);
		}
	}
}

/* Server disconnected, remove it from all dcc records */
static void dcc_server_disconnected(IRC_SERVER_REC *server)
{
    GSList *tmp;

    g_return_if_fail(server != NULL);

    for (tmp = dcc_conns; tmp != NULL; tmp = tmp->next)
    {
        DCC_REC *dcc = tmp->data;

        if (dcc->server == server)
        {
            if (dcc->ircnet == NULL)
                dcc->server = NULL;
            else
            {
                dcc->server = (IRC_SERVER_REC *) server_find_ircnet(dcc->ircnet);
                if (dcc->server != NULL)
                {
                    g_free(dcc->mynick);
                    dcc->mynick = g_strdup(dcc->server->nick);
                }
            }
        }
    }
}

static void dcc_get_address(gchar *str, IPADDR *ip)
{
    gulong addr;

    if (strchr(str, ':') == NULL)
    {
	/* normal IPv4 address */
	if (sscanf(str, "%lu", &addr)!=1)
	    addr = 0;
        ip->family = AF_INET;
	addr = (gulong) ntohl(addr);
	memcpy(&ip->addr, &addr, 4);
    }
    else
    {
	/* IPv6 */
	net_host2ip(str, ip);
    }
}

/* Handle incoming DCC CTCP messages */
static void dcc_ctcp_msg(gchar *data, IRC_SERVER_REC *server, gchar *sender, gchar *sendaddr, gchar *target, DCC_REC *chat)
{
    gchar *params, *type, *arg, *addrstr, *portstr, *sizestr, *str;
    const char *cstr;
    DCC_REC *dcc;
    gulong size;
    gint port;

    g_return_if_fail(data != NULL);
    g_return_if_fail(sender != NULL);

    params = cmd_get_params(data, 5, &type, &arg, &addrstr, &portstr, &sizestr);

    if (sscanf(portstr, "%d", &port) != 1) port = 0;
    if (sscanf(sizestr, "%lu", &size) != 1) size = 0;

    dcc = dcc_create(SWAP_SENDGET(dcc_str2type(type)), -1, sender, arg, server, chat);
    dcc_get_address(addrstr, &dcc->addr);
    net_ip2host(&dcc->addr, dcc->addrstr);
    dcc->port = port;
    dcc->size = size;

    switch (dcc->dcc_type)
    {
	case DCC_TYPE_GET:
	    cstr = settings_get_str("dcc_autoget_masks");
	    /* check that autoget masks match */
	    if (settings_get_bool("dcc_autoget") && (*cstr == '\0' || irc_masks_match(cstr, sender, sendaddr)) &&
                /* check file size limit, FIXME: it's possible to send a bogus file size and then just send what ever sized file.. */
		(settings_get_int("dcc_max_autoget_size") <= 0 || (settings_get_int("dcc_max_autoget_size") > 0 && size <= settings_get_int("dcc_max_autoget_size")*1024)))
            {
                /* automatically get */
                str = g_strdup_printf("GET %s %s", dcc->nick, dcc->arg);
                signal_emit("command dcc", 2, str, server);
                g_free(str);
            }
            else
            {
                /* send request */
                signal_emit("dcc request", 1, dcc);
            }
            break;

	case DCC_TYPE_CHAT:
	    cstr = settings_get_str("dcc_autochat_masks");
	    if (*cstr != '\0' && irc_masks_match(cstr, sender, sendaddr))
	    {
                /* automatically accept chat */
                str = g_strdup_printf("CHAT %s", dcc->nick);
                signal_emit("command dcc", 2, str, server);
                g_free(str);
	    }
	    else
	    {
		/* send request */
		signal_emit("dcc request", 1, dcc);
	    }
	    break;

	case DCC_TYPE_RESUME:
	case DCC_TYPE_ACCEPT:
            /* handle this in dcc-files.c */
            dcc_destroy(dcc);
            break;

        default:
            /* unknown DCC command */
            signal_emit("dcc unknown ctcp", 3, data, sender, sendaddr);
            dcc_destroy(dcc);
            break;
    }

    g_free(params);
}

/* Handle incoming DCC CTCP replies */
static void dcc_ctcp_reply(gchar *data, IRC_SERVER_REC *server, gchar *sender, gchar *sendaddr)
{
    gchar *params, *cmd, *subcmd, *args;
    gint type;
    DCC_REC *dcc;

    g_return_if_fail(data != NULL);
    g_return_if_fail(sender != NULL);

    params = cmd_get_params(data, 3 | PARAM_FLAG_GETREST, &cmd, &subcmd, &args);

    if (g_strcasecmp(cmd, "REJECT") == 0)
    {
        type = dcc_str2type(subcmd);
        dcc = dcc_find_item(type, sender, type == DCC_TYPE_CHAT ? NULL : args);
        if (dcc != NULL)
        {
	    dcc->destroyed = TRUE;
            signal_emit("dcc closed", 1, dcc);
            dcc_destroy(dcc);
        }
    }
    else
    {
        /* unknown dcc ctcp reply */
        signal_emit("dcc unknown reply", 3, data, sender, sendaddr);
    }

    g_free(params);
}

static void dcc_reject(DCC_REC *dcc, IRC_SERVER_REC *server)
{
    gchar *str;

    g_return_if_fail(dcc != NULL);

    if (dcc->server != NULL) server = dcc->server;
    if (server != NULL && (dcc->dcc_type != DCC_TYPE_CHAT || dcc->starttime == 0))
    {
        signal_emit("dcc rejected", 1, dcc);
        str = g_strdup_printf("NOTICE %s :\001DCC REJECT %s %s\001",
                              dcc->nick, dcc_type2str(SWAP_SENDGET(dcc->dcc_type)), dcc->arg);

        irc_send_cmd(server, str);
        g_free(str);
    }

    dcc->destroyed = TRUE;
    signal_emit("dcc closed", 1, dcc);
    dcc_destroy(dcc);
}

/* command: DCC CLOSE */
static void cmd_dcc_close(gchar *data, IRC_SERVER_REC *server)
{
    DCC_REC *dcc;
    GSList *tmp, *next;
    gchar *params, *type, *nick, *arg;
    gboolean found;
    gint itype;

    g_return_if_fail(data != NULL);

    params = cmd_get_params(data, 3, &type, &nick, &arg);

    g_strup(type);
    itype = dcc_str2type(type);
    if (itype == 0)
    {
        signal_emit("dcc error unknown type", 1, type);
        g_free(params);
        return;
    }

    dcc = NULL; found = FALSE;
    for (tmp = dcc_conns; tmp != NULL; tmp = next)
    {
	dcc = tmp->data;
	next = tmp->next;

        if (dcc->dcc_type == itype && g_strcasecmp(nick, dcc->nick) == 0)
        {
	    dcc_reject(dcc, server);
	    found = TRUE;
        }
    }

    if (!found)
        signal_emit("dcc error close not found", 3, type, nick, arg);

    g_free(params);
}

static void cmd_dcc(const char *data, IRC_SERVER_REC *server, WI_IRC_REC *item)
{
	command_runsub("dcc", data, server, item);
}

static int dcc_timeout_func(void)
{
    GSList *tmp, *next;
    time_t now;

    now = time(NULL)-settings_get_int("dcc_timeout");
    for (tmp = dcc_conns; tmp != NULL; tmp = next)
    {
        DCC_REC *rec = tmp->data;

        next = tmp->next;
        if (rec->tagread == -1 && now > rec->created)
        {
            /* timed out. */
            dcc_reject(rec, NULL);
        }
    }
    return 1;
}

static void event_no_such_nick(gchar *data, IRC_SERVER_REC *server)
{
    gchar *params, *nick;
    GSList *tmp, *next;

    g_return_if_fail(data != NULL);

    params = event_get_params(data, 2, NULL, &nick);

    /* check if we've send any dcc requests to this nick.. */
    for (tmp = dcc_conns; tmp != NULL; tmp = next)
    {
        DCC_REC *rec = tmp->data;

        next = tmp->next;
        if (g_strcasecmp(rec->nick, nick) == 0 && rec->starttime == 0)
        {
            /* timed out. */
	    rec->destroyed = TRUE;
            signal_emit("dcc closed", 1, rec);
            dcc_destroy(rec);
        }
    }

    g_free(params);
}

void dcc_init(void)
{
    dcc_conns = NULL;
    dcc_timeouttag = g_timeout_add(1000, (GSourceFunc) dcc_timeout_func, NULL);

    settings_add_bool("dcc", "dcc_autorename", FALSE);
    settings_add_bool("dcc", "dcc_autoget", FALSE);
    settings_add_int("dcc", "dcc_max_autoget_size", 1000);
    settings_add_str("dcc", "dcc_download_path", "~");
    settings_add_int("dcc", "dcc_file_create_mode", 644);
    settings_add_str("dcc", "dcc_autoget_masks", "");
    settings_add_str("dcc", "dcc_autochat_masks", "");

    settings_add_bool("dcc", "dcc_fast_send", TRUE);
    settings_add_str("dcc", "dcc_upload_path", "~");

    settings_add_bool("dcc", "dcc_mirc_ctcp", FALSE);
    settings_add_bool("dcc", "dcc_autodisplay_dialog", TRUE);
    settings_add_int("dcc", "dcc_block_size", 2048);
    settings_add_int("dcc", "dcc_port", 0);
    settings_add_int("dcc", "dcc_timeout", 300);

    signal_add("server connected", (SIGNAL_FUNC) dcc_server_connected);
    signal_add("server disconnected", (SIGNAL_FUNC) dcc_server_disconnected);
    signal_add("ctcp reply dcc", (SIGNAL_FUNC) dcc_ctcp_reply);
    signal_add("ctcp msg dcc", (SIGNAL_FUNC) dcc_ctcp_msg);
    command_bind("dcc", NULL, (SIGNAL_FUNC) cmd_dcc);
    command_bind("dcc close", NULL, (SIGNAL_FUNC) cmd_dcc_close);
    signal_add("event 401", (SIGNAL_FUNC) event_no_such_nick);

    dcc_chat_init();
    dcc_files_init();
}

void dcc_deinit(void)
{
    dcc_chat_deinit();
    dcc_files_deinit();

    signal_remove("server connected", (SIGNAL_FUNC) dcc_server_connected);
    signal_remove("server disconnected", (SIGNAL_FUNC) dcc_server_disconnected);
    signal_remove("ctcp reply dcc", (SIGNAL_FUNC) dcc_ctcp_reply);
    signal_remove("ctcp msg dcc", (SIGNAL_FUNC) dcc_ctcp_msg);
    command_unbind("dcc", (SIGNAL_FUNC) cmd_dcc);
    command_unbind("dcc close", (SIGNAL_FUNC) cmd_dcc_close);
    signal_remove("event 401", (SIGNAL_FUNC) event_no_such_nick);

    g_source_remove(dcc_timeouttag);

    while (dcc_conns != NULL)
        dcc_destroy(dcc_conns->data);
}
