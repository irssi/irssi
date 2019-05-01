/* QUERY_REC definition, used for inheritance */

#include <irssi/src/core/window-item-rec.h>

char *address;
char *server_tag;
time_t last_unread_msg;

unsigned int unwanted:1; /* TRUE if the other side closed or
			    some error occurred (DCC chats!) */
unsigned int destroying:1;
