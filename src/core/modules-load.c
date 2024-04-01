/*
 modules-load.c : irssi

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
#include <irssi/src/core/modules.h>
#include <irssi/src/core/modules-load.h>
#include <irssi/src/core/signals.h>

#include <irssi/src/core/settings.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/misc.h>

/* Returns the module name without path, "lib" prefix or ".so" suffix */
static char *module_get_name(const char *path, int *start, int *end)
{
	const char *name;
	char *module_name, *ptr;

        name = NULL;
	if (*path == '~' || g_path_is_absolute(path)) {
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
			 (int) (ptr-module_name));

	return module_name;
}

/* Returns the root module name for given submodule (eg. perl_core -> perl) */
static char *module_get_root(const char *name, char **prefixes)
{
	int len;

	/* skip any of the prefixes.. */
	if (prefixes != NULL) {
		while (*prefixes != NULL) {
			len = strlen(*prefixes);
			if (strncmp(name, *prefixes, len) == 0 &&
			    name[len] == '_') {
				name += len+1;
				break;
			}
			prefixes++;
		}
	}

	/* skip the _core part */
        len = strlen(name);
	if (len > 5 && g_strcmp0(name+len-5, "_core") == 0)
		return g_strndup(name, len-5);

        return g_strdup(name);
}

/* Returns the sub module name for given submodule (eg. perl_core -> core) */
static char *module_get_sub(const char *name, const char *root)
{
	int rootlen, namelen;

        namelen = strlen(name);
	rootlen = strlen(root);
        g_return_val_if_fail(namelen >= rootlen, g_strdup(name));

	if (strncmp(name, root, rootlen) == 0 &&
	    g_strcmp0(name+rootlen, "_core") == 0)
                return g_strdup("core");

	if (namelen > rootlen && name[namelen-rootlen-1] == '_' &&
	    g_strcmp0(name+namelen-rootlen, root) == 0)
                return g_strndup(name, namelen-rootlen-1);

        return g_strdup(name);
}

static GModule *module_open(const char *name)
{
	GModule *module;
#if GLIB_CHECK_VERSION(2, 75, 0)
	/* in this version of glib, g_module_open knows how to construct system-dependent module
	   file names, and g_module_build_path is deprecated. */

	char *path;

	if (g_path_is_absolute(name) || *name == '~' ||
	    (*name == '.' && name[1] == G_DIR_SEPARATOR))
		path = g_strdup(name);
	else {
		/* first try from home dir */
		path = g_strdup_printf("%s/modules/%s", get_irssi_dir(), name);

		module = g_module_open(path, (GModuleFlags) 0);
		g_free(path);
		if (module != NULL) {
			return module;
		}

		/* module not found from home dir, try global module dir */
		path = g_strdup_printf("%s/%s", MODULEDIR, name);
	}

	module = g_module_open(path, (GModuleFlags) 0);
	g_free(path);
	return module;

#else /* GLib < 2.75.0 */
	/* in this version of glib, we build the module path with g_module_build_path.
	   unfortunately, this is broken on Darwin when compiled with meson. */

	struct stat statbuf;
	char *path, *str;

	if (g_path_is_absolute(name) || *name == '~' ||
	    (*name == '.' && name[1] == G_DIR_SEPARATOR))
		path = g_strdup(name);
	else {
		/* first try from home dir */
		str = g_strdup_printf("%s/modules", get_irssi_dir());
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

#endif
}

static char *module_get_func(const char *rootmodule, const char *submodule,
			     const char *function)
{
	if (g_strcmp0(submodule, "core") == 0)
		return g_strconcat(rootmodule, "_core_", function, NULL);

	if (g_strcmp0(rootmodule, submodule) == 0)
		return g_strconcat(rootmodule, "_", function, NULL);

	return g_strconcat(submodule, "_", rootmodule, "_", function, NULL);
}

#define module_error(error, text, rootmodule, submodule) \
	signal_emit("module error", 4, GINT_TO_POINTER(error), text, \
		    rootmodule, submodule)

/* Returns 1 if ok, 0 if not */
static int module_load_name(const char *path, const char *rootmodule,
			    const char *submodule, int silent)
{
	void (*module_init) (void);
	void (*module_deinit) (void);
	void (*module_version) (int *);
	GModule *gmodule;
        MODULE_REC *module;
	MODULE_FILE_REC *rec;
	gpointer value_version = NULL;
	gpointer value1, value2 = NULL;
	char *versionfunc, *initfunc, *deinitfunc;
	int module_abi_version = 0;
	int valid;

	gmodule = module_open(path);
	if (gmodule == NULL) {
		if (!silent) {
			module_error(MODULE_ERROR_LOAD, g_module_error(),
				     rootmodule, submodule);
		}
		return 0;
	}

	/* get the module's irssi abi version and bail out on mismatch */
	versionfunc = module_get_func(rootmodule, submodule, "abicheck");
	if (!g_module_symbol(gmodule, versionfunc, &value_version)) {
		g_free(versionfunc);
		module_error(MODULE_ERROR_VERSION_MISMATCH, "0",
			     rootmodule, submodule);
		g_module_close(gmodule);
		return 0;
	}
	g_free(versionfunc);
	module_version = value_version;
	module_version(&module_abi_version);
	if (module_abi_version != IRSSI_ABI_VERSION) {
		char *module_abi_versionstr = g_strdup_printf("%d", module_abi_version);
		module_error(MODULE_ERROR_VERSION_MISMATCH, module_abi_versionstr,
			     rootmodule, submodule);
		g_free(module_abi_versionstr);
		g_module_close(gmodule);
		return 0;
	}

	/* get the module's init() and deinit() functions */
	initfunc = module_get_func(rootmodule, submodule, "init");
	deinitfunc = module_get_func(rootmodule, submodule, "deinit");
	valid = g_module_symbol(gmodule, initfunc, &value1) &&
	        g_module_symbol(gmodule, deinitfunc, &value2);
	g_free(initfunc);
	g_free(deinitfunc);

	if (!valid) {
		module_error(MODULE_ERROR_INVALID, NULL,
			     rootmodule, submodule);
		g_module_close(gmodule);
		return 0;
	}

	module_init = value1;
	module_deinit = value2;

	/* Call the module's init() function - it should register itself
	   with module_register() function, abort if it doesn't. */
	module_init();

	module = module_find(rootmodule);
	rec = module == NULL ? NULL :
                g_strcmp0(rootmodule, submodule) == 0 ?
		module_file_find(module, "core") :
		module_file_find(module, submodule);
	if (rec == NULL) {
		rec = module_register_full(rootmodule, submodule, NULL);
		rec->gmodule = gmodule;
		module_file_unload(rec);

		module_error(MODULE_ERROR_INVALID, NULL,
			     rootmodule, submodule);
                return 0;
	}

        rec->module_deinit = module_deinit;
	rec->gmodule = gmodule;
        rec->initialized = TRUE;

	settings_check_module(rec->defined_module_name);

	signal_emit("module loaded", 2, rec->root, rec);
	return 1;
}

static int module_load_prefixes(const char *path, const char *module,
				int start, int end, char **prefixes)
{
        GString *realpath;
        int status, ok;

        /* load module_core */
	realpath = g_string_new(path);
	g_string_insert(realpath, end, "_core");

	/* Don't print the error message the first time, since the module
	   may not have the core part at all. */
	status = module_load_name(realpath->str, module, "core", TRUE);
        ok = status > 0;

	if (prefixes != NULL) {
		/* load all the "prefix modules", like the fe-common, irc,
		   etc. part of the module */
		while (*prefixes != NULL) {
                        g_string_assign(realpath, path);
			g_string_insert_c(realpath, start, '_');
			g_string_insert(realpath, start, *prefixes);

			status = module_load_name(realpath->str, module,
						  *prefixes, TRUE);
			if (status > 0)
				ok = TRUE;

                        prefixes++;
		}
	}

	if (!ok) {
                /* error loading module, print the error message */
		g_string_assign(realpath, path);
		g_string_insert(realpath, end, "_core");
		module_load_name(realpath->str, module, "core", FALSE);
	}

	g_string_free(realpath, TRUE);
        return ok;
}

static int module_load_full(const char *path, const char *rootmodule,
			    const char *submodule, int start, int end,
			    char **prefixes)
{
	MODULE_REC *module;
        int status, try_prefixes;

	if (!g_module_supported())
		return FALSE;

	module = module_find(rootmodule);
	if (module != NULL && (g_strcmp0(submodule, rootmodule) == 0 ||
			       module_file_find(module, submodule) != NULL)) {
                /* module is already loaded */
		module_error(MODULE_ERROR_ALREADY_LOADED, NULL,
			     rootmodule, submodule);
                return FALSE;
	}

	/* check if the given module exists.. */
	try_prefixes = g_strcmp0(rootmodule, submodule) == 0;
	status = module_load_name(path, rootmodule, submodule, try_prefixes);
	if (status <= 0 && try_prefixes) {
		/* nope, try loading the module_core,
		   fe_module, etc. */
		status = module_load_prefixes(path, rootmodule,
					      start, end, prefixes);
	}

	return status > 0;
}

/* Load module - automatically tries to load also the related non-core
   modules given in `prefixes' (like irc, fe, fe_text, ..) */
int module_load(const char *path, char **prefixes)
{
	char *exppath, *name, *submodule, *rootmodule;
        int start, end, ret;

	g_return_val_if_fail(path != NULL, FALSE);

	exppath = convert_home(path);

	name = module_get_name(exppath, &start, &end);
	rootmodule = module_get_root(name, prefixes);
	submodule = module_get_sub(name, rootmodule);
	g_free(name);

	ret = module_load_full(exppath, rootmodule, submodule,
			       start, end, prefixes);

	g_free(rootmodule);
	g_free(submodule);
        g_free(exppath);
        return ret;
}

/* Load a sub module. */
int module_load_sub(const char *path, const char *submodule, char **prefixes)
{
        GString *full_path;
	char *exppath, *name, *rootmodule;
        int start, end, ret;

	g_return_val_if_fail(path != NULL, FALSE);
	g_return_val_if_fail(submodule != NULL, FALSE);

        exppath = convert_home(path);

	name = module_get_name(exppath, &start, &end);
	rootmodule = module_get_root(name, prefixes);
	g_free(name);

        full_path = g_string_new(exppath);
	if (g_strcmp0(submodule, "core") == 0)
		g_string_insert(full_path, end, "_core");
	else {
		g_string_insert_c(full_path, start, '_');
		g_string_insert(full_path, start, submodule);
	}

	ret = module_load_full(full_path->str, rootmodule, submodule,
			       start, end, NULL);

	g_string_free(full_path, TRUE);
	g_free(rootmodule);
	g_free(exppath);
        return ret;
}

static void module_file_deinit_gmodule(MODULE_FILE_REC *file)
{
	/* call the module's deinit() function */
        if (file->module_deinit != NULL)
		file->module_deinit();

	if (file->defined_module_name != NULL) {
		settings_remove_module(file->defined_module_name);
		commands_remove_module(file->defined_module_name);
		signals_remove_module(file->defined_module_name);
	}

	g_module_close(file->gmodule);
}

void module_file_unload(MODULE_FILE_REC *file)
{
	MODULE_REC *root;

        root = file->root;
	root->files = g_slist_remove(root->files, file);

        if (file->initialized)
		signal_emit("module unloaded", 2, file->root, file);

	if (file->gmodule != NULL)
                module_file_deinit_gmodule(file);

	g_free(file->name);
	g_free(file->defined_module_name);
	g_free(file);

	if (root->files == NULL && g_slist_find(modules, root) != NULL)
                module_unload(root);
}

void module_unload(MODULE_REC *module)
{
	g_return_if_fail(module != NULL);

	modules = g_slist_remove(modules, module);

	signal_emit("module unloaded", 1, module);

	while (module->files != NULL)
                module_file_unload(module->files->data);

        g_free(module->name);
	g_free(module);
}
