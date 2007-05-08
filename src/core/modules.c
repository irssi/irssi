/*
 modules.c : irssi

    Copyright (C) 1999-2001 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include "modules.h"
#include "signals.h"

GSList *modules;

static GHashTable *uniqids, *uniqstrids;
static GHashTable *idlookup, *stridlookup;
static int next_uniq_id;

void *module_check_cast(void *object, int type_pos, const char *id)
{
	return object == NULL || module_find_id(id,
		G_STRUCT_MEMBER(int, object, type_pos)) == -1 ? NULL : object;
}

void *module_check_cast_module(void *object, int type_pos,
			       const char *module, const char *id)
{
	const char *str;

	if (object == NULL)
		return NULL;

	str = module_find_id_str(module,
				 G_STRUCT_MEMBER(int, object, type_pos));
	return str == NULL || strcmp(str, id) != 0 ? NULL : object;
}

/* return unique number across all modules for `id' */
int module_get_uniq_id(const char *module, int id)
{
        GHashTable *ids;
	gpointer origkey, uniqid, idp;
	int ret;

	g_return_val_if_fail(module != NULL, -1);

	ids = g_hash_table_lookup(idlookup, module);
	if (ids == NULL) {
		/* new module */
		ids = g_hash_table_new((GHashFunc) g_direct_hash,
				       (GCompareFunc) g_direct_equal);
		g_hash_table_insert(idlookup, g_strdup(module), ids);
	}

	idp = GINT_TO_POINTER(id);
	if (!g_hash_table_lookup_extended(ids, idp, &origkey, &uniqid)) {
		/* not found */
		ret = next_uniq_id++;
                g_hash_table_insert(ids, idp, GINT_TO_POINTER(ret));
                g_hash_table_insert(uniqids, GINT_TO_POINTER(ret), idp);
	} else {
                ret = GPOINTER_TO_INT(uniqid);
	}

	return ret;
}

/* return unique number across all modules for `id' */
int module_get_uniq_id_str(const char *module, const char *id)
{
        GHashTable *ids;
	gpointer origkey, uniqid;
	int ret;

	g_return_val_if_fail(module != NULL, -1);

	ids = g_hash_table_lookup(stridlookup, module);
	if (ids == NULL) {
		/* new module */
		ids = g_hash_table_new((GHashFunc) g_str_hash,
				       (GCompareFunc) g_str_equal);
		g_hash_table_insert(stridlookup, g_strdup(module), ids);
	}

	if (!g_hash_table_lookup_extended(ids, id, &origkey, &uniqid)) {
		/* not found */
		char *saveid;

		saveid = g_strdup(id);
		ret = next_uniq_id++;
                g_hash_table_insert(ids, saveid, GINT_TO_POINTER(ret));
                g_hash_table_insert(uniqstrids, GINT_TO_POINTER(ret), saveid);
	} else {
                ret = GPOINTER_TO_INT(uniqid);
	}

	return ret;
}

/* returns the original module specific id, -1 = not found */
int module_find_id(const char *module, int uniqid)
{
	GHashTable *idlist;
	gpointer origkey, id;
	int ret;

	g_return_val_if_fail(module != NULL, -1);

	if (!g_hash_table_lookup_extended(uniqids, GINT_TO_POINTER(uniqid),
					  &origkey, &id))
		return -1;

	/* check that module matches */
	idlist = g_hash_table_lookup(idlookup, module);
	if (idlist == NULL)
		return -1;

	ret = GPOINTER_TO_INT(id);
	if (!g_hash_table_lookup_extended(idlist, id, &origkey, &id) ||
	    GPOINTER_TO_INT(id) != uniqid)
		ret = -1;

	return ret;
}

/* returns the original module specific id, NULL = not found */
const char *module_find_id_str(const char *module, int uniqid)
{
	GHashTable *idlist;
	gpointer origkey, id;
	const char *ret;

	g_return_val_if_fail(module != NULL, NULL);

	if (!g_hash_table_lookup_extended(uniqstrids, GINT_TO_POINTER(uniqid),
					  &origkey, &id))
		return NULL;

	/* check that module matches */
	idlist = g_hash_table_lookup(stridlookup, module);
	if (idlist == NULL)
		return NULL;

	ret = id;
	if (!g_hash_table_lookup_extended(idlist, id, &origkey, &id) ||
	    GPOINTER_TO_INT(id) != uniqid)
		ret = NULL;

	return ret;
}

static void uniq_destroy(gpointer key, gpointer value)
{
        g_hash_table_remove(uniqids, value);
}

static void uniq_destroy_str(gpointer key, gpointer value)
{
        g_hash_table_remove(uniqstrids, value);
        g_free(key);
}

/* Destroy unique IDs from `module'. This function is automatically called
   when module is destroyed with module's name as the parameter. */
void module_uniq_destroy(const char *module)
{
	GHashTable *idlist;
	gpointer key, value;

	if (g_hash_table_lookup_extended(idlookup, module, &key, &value)) {
		idlist = value;

		g_hash_table_remove(idlookup, key);
		g_free(key);

		g_hash_table_foreach(idlist, (GHFunc) uniq_destroy, NULL);
		g_hash_table_destroy(idlist);
	}

	if (g_hash_table_lookup_extended(stridlookup, module, &key, &value)) {
		idlist = value;

		g_hash_table_remove(stridlookup, key);
		g_free(key);

		g_hash_table_foreach(idlist, (GHFunc) uniq_destroy_str, NULL);
		g_hash_table_destroy(idlist);
	}
}

/* Register a new module. The `name' is the root module name, `submodule'
   specifies the current module to be registered (eg. "perl", "fe").
   The module is registered as statically loaded by default. */
MODULE_FILE_REC *module_register_full(const char *name, const char *submodule,
				      const char *defined_module_name)
{
	MODULE_REC *module;
        MODULE_FILE_REC *file;

	module = module_find(name);
	if (module == NULL) {
		module = g_new0(MODULE_REC, 1);
		module->name = g_strdup(name);

                modules = g_slist_append(modules, module);
	}

	file = module_file_find(module, submodule);
	if (file != NULL)
		return file;

	file = g_new0(MODULE_FILE_REC, 1);
	file->root = module;
	file->name = g_strdup(submodule);
        file->defined_module_name = g_strdup(defined_module_name);

	module->files = g_slist_append(module->files, file);
        return file;
}

MODULE_REC *module_find(const char *name)
{
	GSList *tmp;

	for (tmp = modules; tmp != NULL; tmp = tmp->next) {
		MODULE_REC *rec = tmp->data;

		if (g_strcasecmp(rec->name, name) == 0)
			return rec;
	}

	return NULL;
}

MODULE_FILE_REC *module_file_find(MODULE_REC *module, const char *name)
{
	GSList *tmp;

	for (tmp = module->files; tmp != NULL; tmp = tmp->next) {
		MODULE_FILE_REC *rec = tmp->data;

		if (strcmp(rec->name, name) == 0)
                        return rec;
	}

        return NULL;
}

static void uniq_get_modules(char *key, void *value, GSList **list)
{
        *list = g_slist_append(*list, g_strdup(key));
}

void modules_init(void)
{
	modules = NULL;

	idlookup = g_hash_table_new((GHashFunc) g_str_hash,
				    (GCompareFunc) g_str_equal);
	uniqids = g_hash_table_new((GHashFunc) g_direct_hash,
				   (GCompareFunc) g_direct_equal);

	stridlookup = g_hash_table_new((GHashFunc) g_str_hash,
				       (GCompareFunc) g_str_equal);
	uniqstrids = g_hash_table_new((GHashFunc) g_direct_hash,
				      (GCompareFunc) g_direct_equal);
	next_uniq_id = 0;
}

void modules_deinit(void)
{
	GSList *list;

	list = NULL;
	g_hash_table_foreach(idlookup, (GHFunc) uniq_get_modules, &list);
	g_hash_table_foreach(stridlookup, (GHFunc) uniq_get_modules, &list);

	while (list != NULL) {
		module_uniq_destroy(list->data);
		g_free(list->data);
		list = g_slist_remove(list, list->data);
	}

	g_hash_table_destroy(idlookup);
	g_hash_table_destroy(stridlookup);
	g_hash_table_destroy(uniqids);
	g_hash_table_destroy(uniqstrids);
}
