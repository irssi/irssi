#include <common.h>

#include "core/network.h"

#define FLOOD_TIMEOUT 1

typedef struct
{
    gchar *name;
    GList *nicks;
}
SERVER_CHANNEL_REC;

GList *channels;
gchar *clientnick, clienthost[MAX_IP_LEN];

GIOChannel *clienth;

#ifdef MEM_DEBUG
/* we don't -lgmodule.. */
#undef g_module_build_path
char *g_module_build_path(const char *dir, const char *module)
{
        return NULL;
}
#endif

/* Read a line */
gint read_line(GIOChannel *handle, GString *output, GString *buffer)
{
    gchar tmpbuf[512];
    gint recvlen, pos;

    g_return_val_if_fail(handle != NULL, -1);
    g_return_val_if_fail(output != NULL, -1);
    g_return_val_if_fail(buffer != NULL, -1);

    g_string_truncate(output, 0);

    recvlen = net_receive(handle, tmpbuf, sizeof(tmpbuf)-1);

    if (recvlen <= 0)
    {
        if (buffer->len > 0)
        {
            /* no new data got but still something in buffer.. */
            for (pos = 0; pos < buffer->len; pos++)
            {
                if (buffer->str[pos] == 13 || buffer->str[pos] == 10)
                {
                    recvlen = 0;
                    break;
                }
            }
            if (recvlen < 0 && buffer->len > 0)
            {
                /* connection closed and last line is missing \n ..
                   just add it so we can see if it had anything useful.. */
                recvlen = 0;
                g_string_append_c(buffer, '\n');
            }
        }

        if (recvlen < 0) return -1;
    }
    else
    {
        /* append received data to buffer */
        tmpbuf[recvlen] = '\0';
        g_string_append(buffer, tmpbuf);
    }

    for (pos = 0; pos < buffer->len; pos++)
    {
        if (buffer->str[pos] == 13 || buffer->str[pos] == 10)
        {
            /* end of line */
            buffer->str[pos] = '\0';
            g_string_assign(output, buffer->str);

            if (buffer->str[pos] == 13 && buffer->str[pos+1] == 10)
            {
                /* skip \n too */
                pos++;
            }

            g_string_erase(buffer, 0, pos+1);
            return 1;
        }
    }

    /* EOL wasn't found, wait for more data.. */
    return 0;
}
void client_send(char *text)
{
    if (strlen(text) > 508) text[508] = 0;
    net_transmit(clienth, text, strlen(text));
    net_transmit(clienth, "\r\n", 2);
}

void makerand(char *str, int len)
{
    for (; len > 0; len--)
        *str++ = (rand() % 20)+'A';
}

void makerand2(char *str, int len)
{
#if 1
    gchar c;

    while (len > 0)
    {
	c = (rand() % 20)+ 'A';
	if (c != 0 && c != 13 && c != 10)
	{
	    *str++ = c;
	    len--;
	}
    }
#else
    makerand(str, len);
#endif
}

void send_cmd(void)
{
    static gint nicks = 0;
    GList *tmp;
    char str[512];
    int pos;

    /* send msg to every channel */
    str[511] = '\0';
    for (tmp = g_list_first(channels); tmp != NULL; tmp = tmp->next)
    {
        SERVER_CHANNEL_REC *rec = tmp->data;

        makerand(str, 511);
        str[0] = ':';
        str[10] = '!';
        str[20] = '@';

        switch (rand() % 10)
	{
            case 0:
                /* join */
                pos = 2+sprintf(str+2, "%d", nicks++); /* don't use same nick twice */
                str[pos] = '-';
                str[10] = '\0';
                g_list_append(rec->nicks, g_strdup(str+1));
                str[10] = '!';
                sprintf(str+30, " JOIN :%s", rec->name);
		break;
            case 1:
                /* part */
                if (g_list_length(rec->nicks) > 1 && rand() % 3 == 0)
                {
                    gchar *nick;

                    nick = g_list_nth(rec->nicks, rand()%(g_list_length(rec->nicks)-1)+1)->data;
                    if (rand() % 3 == 0)
                        sprintf(str, ":kicker!some@where KICK %s %s :go away", rec->name, nick);
                    else if (rand() % 3 == 0)
                        sprintf(str, ":%s!dunno@where QUIT %s :i'm outta here", nick, rec->name);
                    else
                        sprintf(str, ":%s!dunno@where PART %s", nick, rec->name);
                    rec->nicks = g_list_remove(rec->nicks, nick);
                    g_free(nick);
                }
                else
                    str[0] = '\0';
                break;
            case 2:
                /* nick change */
                if (g_list_length(rec->nicks) > 1)
                {
                    gchar *nick;

                    nick = g_list_nth(rec->nicks, rand()%(g_list_length(rec->nicks)-1)+1)->data;
                    pos = sprintf(str, ":%s!dunno@where NICK ", nick);
                    str[pos] = '_';
                    str[50] = '\0';
                    rec->nicks = g_list_remove(rec->nicks, nick);
                    rec->nicks = g_list_append(rec->nicks, g_strdup(str+pos));
                    g_free(nick);
                }
                else
                    str[0] = '\0';
                break;
            case 3:
                /* topic */
                pos = 30+sprintf(str+30, " TOPIC %s :", rec->name);
                str[pos] = 'x';
                break;
            case 4:
                /* mode */
                sprintf(str+30, " MODE %s :%cnt", rec->name, (rand() & 1) ? '+' : '-');
                break;
            case 5:
                /* notice */
                pos = 30+sprintf(str+30, " NOTICE %s :", rec->name);
                str[pos] = 'X';
		break;
            case 6:
                /* nick mode change */
                if (g_list_length(rec->nicks) > 1)
                {
                    gchar *nick;

                    nick = g_list_nth(rec->nicks, rand()%(g_list_length(rec->nicks)-1)+1)->data;
		    pos = sprintf(str, ":server MODE %s +%c %s", rec->name, rand()&1 ? 'o' : 'v', nick);
                    str[pos] = '_';
                    str[50] = '\0';
                    rec->nicks = g_list_remove(rec->nicks, nick);
                    rec->nicks = g_list_append(rec->nicks, g_strdup(str+pos));
                    g_free(nick);
                }
                else
                    str[0] = '\0';
                break;
            default:
		pos = 30+sprintf(str+30, " PRIVMSG %s :", rec->name);
		makerand2(str+pos, 511-pos);
                if (rand() % 4 == 0)
                {
                    pos += sprintf(str+pos, "\001ACTION ");
                    str[510] = 1;
                }
                else if (rand() % 10 == 0)
                {
                    pos += sprintf(str+pos, "\001VERSION\001");
                    pos++;
                }
                else if (rand() % 2 == 0)
                {
                    pos += sprintf(str+pos, "%s: ", clientnick);
		}
		str[pos] = 'X';
		break;
        }

        client_send(str);
    }
    makerand(str, 511);
    str[0] = ':';
    str[10] = '!';
    str[20] = '@';
    switch (rand() % 11)
    {
	case 0:
            /* join */
            if (g_list_length(channels) < 20)
            {
                SERVER_CHANNEL_REC *rec;
                int n, pos;

                n = (rand()%20)+25;
                pos = sprintf(str, ":%s!%s JOIN :", clientnick, clienthost);
                str[pos] = '#';
                str[n] = '\0';

                rec = g_new(SERVER_CHANNEL_REC, 1);
                rec->name = g_strdup(str+pos);
                rec->nicks = g_list_append(NULL, g_strdup(clientnick));

                channels = g_list_append(channels, rec);
                client_send(str);

                sprintf(str, ":server 353 %s = %s :@%s", clientnick, rec->name, clientnick);
                client_send(str);
                sprintf(str, ":server 366 %s %s :End of /NAMES list.", clientnick, rec->name);
            }
            else
                str[0] = '\0';
            break;
	case 1:
            /* leave channel (by kick) */
            if (g_list_length(channels) > 3)
            {
                SERVER_CHANNEL_REC *chan;

                chan = g_list_nth(channels, rand()%g_list_length(channels))->data;
                if (rand() % 3 != 0)
                {
                    pos = sprintf(str, ":%s!%s PART %s :", clientnick, clienthost, chan->name);
                    str[pos] = 'x';
                }
                else
                {
                    str[0] = ':';
                    sprintf(str+30, " KICK %s %s :byebye", chan->name, clientnick);
                }

                g_free(chan->name);
                g_list_foreach(chan->nicks, (GFunc) g_free, NULL); g_list_free(chan->nicks);
                g_free(chan);
                channels = g_list_remove(channels, chan);
            }
            else
                str[0] = '\0';
            break;
        case 2:
            /* ctcp version */
            sprintf(str+30, " PRIVMSG %s :\001VERSION\001", clientnick);
            break;
        case 3:
            /* ctcp ping */
            sprintf(str+30, " PRIVMSG %s :\001PING\001", clientnick);
            break;
        case 4:
            /* user mode */
            sprintf(str+30, " MODE %s :%ciw", clientnick, (rand() & 1) ? '+' : '-');
            break;
        case 5:
            /* msg */
            pos = 30+sprintf(str+30, " PRIVMSG %s :", clientnick);
            str[pos] = 'X';
            break;
        case 6:
            /* notice */
            pos = 30+sprintf(str+30, " NOTICE %s :", clientnick);
            str[pos] = 'X';
            break;
        case 7:
            /* invite */
            pos = 30+sprintf(str+30, " INVITE %s ", clientnick);
            str[pos] = 'X';
            break;
        case 8:
            /* error */
            pos = sprintf(str, ":server ERROR :");
            str[pos] = 'X';
            break;
        case 9:
            /* wallops */
            pos = sprintf(str, ":server WALLOPS :");
            str[pos] = 'X';
            break;
        case 10:
            /* ping */
            pos = sprintf(str, ":server PING :");
            str[pos] = 'X';
	    break;
    }
    client_send(str);
}

void handle_command(char *str)
{
    if (strncmp(str, "NICK ", 5) == 0)
    {
        clientnick = g_strdup(str+5); /* got the nick */
    }
}

int main(void)
{
    static fd_set fdset;
    struct timeval tv;
    GIOChannel *serverh;
    int port;

    srand(0);
    port = 6660;
    serverh = net_listen(NULL, &port);
    if (serverh == NULL)
    {
	printf("listen()\n");
	return 1;
    }

    clienth = NULL; channels = NULL;
    for (;;)
    {
        FD_ZERO(&fdset);
        if (clienth != NULL) FD_SET(g_io_channel_unix_get_fd(clienth), &fdset);
        FD_SET(g_io_channel_unix_get_fd(serverh), &fdset);

        tv.tv_sec = 0;
        tv.tv_usec = FLOOD_TIMEOUT;
	if (select((g_io_channel_unix_get_fd(serverh) > g_io_channel_unix_get_fd(clienth) ?
		    g_io_channel_unix_get_fd(serverh) : g_io_channel_unix_get_fd(clienth))+1, &fdset, NULL, NULL, &tv) <= 0)
        {
		/* nothing happened, bug the client with some commands.. */
		if (clienth != NULL && clientnick != NULL) send_cmd();
        }
        else
	{
            if (FD_ISSET(g_io_channel_unix_get_fd(serverh), &fdset))
            {
                /* client connecting! */
                if (clienth != NULL)
                {
                    /* only one client allowed.. */
                    GIOChannel *handle;

                    handle = net_accept(serverh, NULL, &port);
                    if (handle != NULL)
                    {
                        client_send("Only one client allowed");
                        net_disconnect(handle);
                        continue;
                    }
                }
                else
		{
		    IPADDR clientip;

                    clienth = net_accept(serverh, &clientip, &port);
                    if (clienth != NULL)
		    {
			net_ip2host(&clientip, clienthost);
                        client_send(":server 001 pla");
                        client_send(":server 002 plapla");
                        client_send(":server 003 plaplapla");
                        client_send(":server 004 connected!");
                    }
                }
            }
            else
            {
                /* clients sending something.. */
                GString *str, *buf;
                int ret;

                str = g_string_new(NULL);
                buf = g_string_new(NULL);
                do
                {
                    ret = read_line(clienth, str, buf);
                    if (ret == -1)
                    {
                        /* client disconnected */
                        net_disconnect(clienth);
                        clienth = NULL;
                        break;
                    }
                    if (ret == 1) handle_command(str->str);
                }
                while (ret == 1);
                g_string_free(str, TRUE);
                g_string_free(buf, TRUE);
            }
        }
    }

    return 0;
}
