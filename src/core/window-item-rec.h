/* WI_ITEM_REC definition, used for inheritance */

int type; /* module_get_uniq_id("CHANNEL/QUERY/xxx", 0) */
int chat_type; /* chat_protocol_lookup(xx) */
GHashTable *module_data;

void *window;
STRUCT_SERVER_REC *server;
char *visible_name;

time_t createtime;
int data_level;
char *hilight_color;

void (*destroy)(WI_ITEM_REC *item);

const char *(*get_target)(WI_ITEM_REC *item);
#define window_item_get_target(item) \
	((item)->get_target(item))

#undef STRUCT_SERVER_REC
