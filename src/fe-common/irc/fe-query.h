#ifndef __FE_QUERY_H
#define __FE_QUERY_H

/* Return query where to put the private message. */
QUERY_REC *privmsg_get_query(IRC_SERVER_REC *server, const char *nick, int own);

#endif
