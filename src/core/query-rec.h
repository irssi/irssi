/* QUERY_REC definition, used for inheritance */

#include "window-item-rec.h"

char *name;
char *address;
char *server_tag;
time_t last_unread_msg;

unsigned int unwanted:1; /* TRUE if the other side closed or
			    some error occured (DCC chats!) */
unsigned int destroying:1;
