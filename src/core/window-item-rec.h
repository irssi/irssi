/* WI_ITEM_REC definition, used for inheritance */

int type; /* module_get_uniq_id("CHANNEL/QUERY/xxx", 0) */
int chat_type; /* chat_protocol_lookup(xx) */
GHashTable *module_data;

void *window;
STRUCT_SERVER_REC *server;
char *name;

time_t createtime;
int data_level;
char *hilight_color;

#undef STRUCT_SERVER_REC
