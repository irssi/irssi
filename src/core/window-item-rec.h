/* WI_ITEM_REC definition, used for inheritance */

int type; /* window item type - channel/query/.. */
int chat_type; /* chat server type - irc/silc/.. */
GHashTable *module_data;

STRUCT_SERVER_REC *server;
char *name;

time_t createtime;
int new_data;
int last_color;  /* if NEWDATA_HILIGHT is set, color number could be specified here */

#undef STRUCT_SERVER_REC
