#ifndef __MODULES_H
#define __MODULES_H

#define MODULE_DATA_INIT(rec) \
        (rec)->module_data = g_hash_table_new(g_str_hash, g_str_equal)

#define MODULE_DATA_DEINIT(rec) \
        g_hash_table_destroy((rec)->module_data)

#define MODULE_DATA_SET(rec, data) \
	g_hash_table_insert((rec)->module_data, MODULE_NAME, data)

#define MODULE_DATA_UNSET(rec) \
	g_hash_table_remove((rec)->module_data, MODULE_NAME)

#define MODULE_DATA(rec) \
	g_hash_table_lookup((rec)->module_data, MODULE_NAME)


#ifdef HAVE_GMODULE
#  define MODULE_IS_STATIC(rec) \
        ((rec)->gmodule == NULL)
#else
#  define MODULE_IS_STATIC(rec) TRUE
#endif

enum {
	MODULE_ERROR_ALREADY_LOADED,
	MODULE_ERROR_LOAD,
	MODULE_ERROR_INVALID
};

typedef struct _MODULE_REC MODULE_REC;

typedef struct {
	MODULE_REC *root;
	char *name;
        char *defined_module_name;
	void (*module_deinit) (void);

#ifdef HAVE_GMODULE
	GModule *gmodule; /* static, if NULL */
#endif
	unsigned int initialized:1;
} MODULE_FILE_REC;

struct _MODULE_REC {
	char *name;
        GSList *files; /* list of modules that belong to this root module */
};

extern GSList *modules;

/* Register a new module. The `name' is the root module name, `submodule'
   specifies the current module to be registered (eg. "perl", "fe").
   The module is registered as statically loaded by default. */
MODULE_FILE_REC *module_register_full(const char *name, const char *submodule,
				      const char *defined_module_name);
#define module_register(name, submodule) \
        module_register_full(name, submodule, MODULE_NAME)

MODULE_REC *module_find(const char *name);
MODULE_FILE_REC *module_file_find(MODULE_REC *module, const char *name);

#define MODULE_CHECK_CAST(object, cast, type_field, id) \
	((cast *) module_check_cast(object, offsetof(cast, type_field), id))
#define MODULE_CHECK_CAST_MODULE(object, cast, type_field, module, id) \
	((cast *) module_check_cast_module(object, \
				offsetof(cast, type_field), module, id))
void *module_check_cast(void *object, int type_pos, const char *id);
void *module_check_cast_module(void *object, int type_pos,
			       const char *module, const char *id);

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
