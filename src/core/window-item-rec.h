/* WI_ITEM_REC definition, used for inheritance */

int type; /* module_get_uniq_id("CHANNEL/QUERY/xxx", 0) */
int chat_type; /* chat_protocol_lookup(xx) */
GHashTable *module_data;

STRUCT_SERVER_REC *server;
char *name;

time_t createtime;
int new_data;
int last_color;  /* if NEWDATA_HILIGHT is set, color number could be specified here */

#undef STRUCT_SERVER_REC
