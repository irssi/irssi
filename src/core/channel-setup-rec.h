int type; /* module_get_uniq_id("CHANNEL SETUP", 0) */
int chat_type; /* chat_protocol_lookup(xx) */

char *name;
char *chatnet;
char *password;

char *botmasks;
char *autosendcmd;

unsigned int autojoin:1;
GHashTable *module_data;
