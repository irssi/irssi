#ifndef __MODULES_H
#define __MODULES_H

enum {
	MODULE_ERROR_ALREADY_LOADED,
	MODULE_ERROR_LOAD,
	MODULE_ERROR_INVALID
};

typedef struct {
	char *name;
	GModule *gmodule;
} MODULE_REC;

extern GSList *modules;

MODULE_REC *module_find(const char *name);

int module_load(const char *path);
void module_unload(MODULE_REC *module);

#define MODULE_DATA_INIT(rec) \
        (rec)->module_data = g_hash_table_new(g_str_hash, g_str_equal)

#define MODULE_DATA_DEINIT(rec) \
        g_hash_table_destroy((rec)->module_data)

#define MODULE_DATA_SET(rec, data) \
	g_hash_table_insert((rec)->module_data, MODULE_NAME, data)

#define MODULE_DATA(rec) \
	g_hash_table_lookup((rec)->module_data, MODULE_NAME)

/* return unique number across all modules for `id' */
int module_get_uniq_id(const char *module, int id);
/* return unique number across all modules for `id'. */
int module_get_uniq_id_str(const char *module, const char *id);

/* returns the original module specific id, -1 = not found */
int module_find_id(const char *module, int uniqid);
/* returns the original module specific id, NULL = not found */
const char *module_find_id_str(const char *module, int uniqid);

/* Destroy unique IDs from `module'. This function is automatically called
   when module is destroyed with module's name as the parameter. */
void module_uniq_destroy(const char *module);

void modules_init(void);
void modules_deinit(void);

#endif
