/*
 modules.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "modules.h"
#include "signals.h"

#include "commands.h"
#include "settings.h"

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
	gpointer key;

	if (g_hash_table_lookup_extended(idlookup, module, &key,
					 (gpointer *) &idlist)) {
		g_hash_table_remove(idlookup, key);
		g_free(key);

		g_hash_table_foreach(idlist, (GHFunc) uniq_destroy, NULL);
		g_hash_table_destroy(idlist);
	}

	if (g_hash_table_lookup_extended(stridlookup, module, &key,
					 (gpointer *) &idlist)) {
		g_hash_table_remove(stridlookup, key);
		g_free(key);

		g_hash_table_foreach(idlist, (GHFunc) uniq_destroy_str, NULL);
		g_hash_table_destroy(idlist);
	}
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

static char *module_get_name(const char *path, int *start, int *end)
{
	const char *name;
	char *module_name, *ptr;

        name = NULL;
	if (g_path_is_absolute(path)) {
		name = strrchr(path, G_DIR_SEPARATOR);
                if (name != NULL) name++;
	}

	if (name == NULL)
		name = path;

	if (strncmp(name, "lib", 3) == 0)
		name += 3;

	module_name = g_strdup(name);
	ptr = strchr(module_name, '.');
	if (ptr != NULL) *ptr = '\0';

	*start = (int) (name-path);
	*end = *start + (ptr == NULL ? strlen(name) :
			 (int) (module_name-ptr));

	return module_name;
}

#ifdef HAVE_GMODULE
static GModule *module_open(const char *name)
{
	struct stat statbuf;
	GModule *module;
	char *path, *str;

	if (g_path_is_absolute(name) ||
	    (*name == '.' && name[1] == G_DIR_SEPARATOR))
		path = g_strdup(name);
	else {
		/* first try from home dir */
		str = g_strdup_printf("%s/.irssi/modules", g_get_home_dir());
		path = g_module_build_path(str, name);
		g_free(str);

		if (stat(path, &statbuf) == 0) {
			module = g_module_open(path, (GModuleFlags) 0);
			g_free(path);
			return module;
		}

		/* module not found from home dir, try global module dir */
		g_free(path);
		path = g_module_build_path(MODULEDIR, name);
	}

	module = g_module_open(path, (GModuleFlags) 0);
	g_free(path);
	return module;
}

#define module_error(error, module, text) \
	signal_emit("module error", 3, GINT_TO_POINTER(error), module, text)

static int module_load_name(const char *path, const char *name, int silent)
{
	void (*module_init) (void);
	GModule *gmodule;
	MODULE_REC *rec;
	char *initfunc;

	gmodule = module_open(path);
	if (gmodule == NULL) {
		if (!silent) {
			module_error(MODULE_ERROR_LOAD, name,
				     g_module_error());
		}
		return FALSE;
	}

	/* get the module's init() function */
	initfunc = g_strconcat(name, "_init", NULL);
	if (!g_module_symbol(gmodule, initfunc, (gpointer *) &module_init)) {
		if (!silent)
			module_error(MODULE_ERROR_INVALID, name, NULL);
		g_module_close(gmodule);
		g_free(initfunc);
		return FALSE;
	}
	g_free(initfunc);

	rec = g_new0(MODULE_REC, 1);
	rec->name = g_strdup(name);
        rec->gmodule = gmodule;
	modules = g_slist_append(modules, rec);

	module_init();
	settings_check_module(name);

	signal_emit("module loaded", 1, rec);
	return TRUE;
}
#endif

/* Load module - automatically tries to load also the related non-core
   modules given in `prefixes' (like irc, fe, fe_text, ..) */
int module_load(const char *path, char **prefixes)
{
#ifdef HAVE_GMODULE
        GString *realpath;
	char *name, *pname;
	int ret, start, end;

	g_return_val_if_fail(path != NULL, FALSE);

	if (!g_module_supported())
		return FALSE;

	name = module_get_name(path, &start, &end);
	if (module_find(name)) {
		module_error(MODULE_ERROR_ALREADY_LOADED, name, NULL);
                g_free(name);
		return FALSE;
	}

        /* load "module_core" instead of "module" if it exists */
	realpath = g_string_new(path);
	g_string_insert(realpath, end, "_core");

        pname = g_strconcat(name, "_core", NULL);
	ret = module_load_name(realpath->str, pname, TRUE);
	g_free(pname);

	if (!ret) {
                /* load "module" - complain if it's not found */
		ret = module_load_name(path, name, FALSE);
	} else if (prefixes != NULL) {
		/* load all the "prefix modules", like the fe-common, irc,
		   etc. part of the module */
		while (*prefixes != NULL) {
                        g_string_assign(realpath, path);
			g_string_insert(realpath, start, "_");
			g_string_insert(realpath, start, *prefixes);

                        pname = g_strconcat(*prefixes, "_", name, NULL);
			module_load_name(realpath->str, pname, TRUE);
			g_free(pname);

                        prefixes++;
		}
	}

        g_string_free(realpath, TRUE);
	g_free(name);
	return ret;
#else
        return FALSE;
#endif
}

void module_unload(MODULE_REC *module)
{
#ifdef HAVE_GMODULE
	void (*module_deinit) (void);
	char *deinitfunc;

	g_return_if_fail(module != NULL);

	modules = g_slist_remove(modules, module);

	signal_emit("module unloaded", 1, module);

	/* call the module's deinit() function */
	deinitfunc = g_strconcat(module->name, "_deinit", NULL);
	if (g_module_symbol(module->gmodule, deinitfunc,
			    (gpointer *) &module_deinit))
		module_deinit();
	g_free(deinitfunc);

        settings_remove_module(module->name);
	commands_remove_module(module->name);
	signals_remove_module(module->name);

	g_module_close(module->gmodule);
	g_free(module->name);
	g_free(module);
#endif
}

static void uniq_get_modules(char *key, void *value, GSList **list)
{
        *list = g_slist_append(*list, key);
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
		list = g_slist_remove(list, list->data);
	}

	g_hash_table_destroy(idlookup);
	g_hash_table_destroy(stridlookup);
	g_hash_table_destroy(uniqids);
	g_hash_table_destroy(uniqstrids);
}
