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

static GHashTable *uniqids, *uniqstrids;
static GHashTable *idlookup, *stridlookup;
static int next_uniq_id;

/* return unique number across all modules for `id' */
int module_get_uniq_id(const char *module, int id)
{
        GHashTable *ids;
	gpointer origkey, uniqid;
	int ret;

	g_return_val_if_fail(module != NULL, -1);

	ids = g_hash_table_lookup(idlookup, module);
	if (ids == NULL) {
		/* new module */
		ids = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);
		g_hash_table_insert(idlookup, g_strdup(module), ids);
	}

	if (!g_hash_table_lookup_extended(ids, GINT_TO_POINTER(id), &origkey, &uniqid)) {
		/* not found */
		ret = next_uniq_id++;
                g_hash_table_insert(ids, GINT_TO_POINTER(id), GINT_TO_POINTER(ret));
                g_hash_table_insert(uniqids, GINT_TO_POINTER(ret), GINT_TO_POINTER(id));
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
		ids = g_hash_table_new((GHashFunc) g_str_hash, (GCompareFunc) g_str_equal);
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
	GHashTable *ids;
	gpointer origkey, id;
	int ret;

	g_return_val_if_fail(module != NULL, -1);

	ret = g_hash_table_lookup_extended(uniqids, GINT_TO_POINTER(uniqid), &origkey, &id) ?
		GPOINTER_TO_INT(id) : -1;

	if (ret != -1) {
		/* check that module matches */
		ids = g_hash_table_lookup(idlookup, module);
		if (ids == NULL || !g_hash_table_lookup_extended(ids, GINT_TO_POINTER(ret), &origkey, &id))
			ret = -1;
	}

	return ret;
}

/* returns the original module specific id, NULL = not found */
const char *module_find_id_str(const char *module, int uniqid)
{
	GHashTable *ids;
	gpointer origkey, id;
	const char *ret;

	g_return_val_if_fail(module != NULL, NULL);

	ret = g_hash_table_lookup_extended(uniqstrids, GINT_TO_POINTER(uniqid),
					   &origkey, &id) ? id : NULL;

	if (ret != NULL) {
		/* check that module matches */
		ids = g_hash_table_lookup(stridlookup, module);
		if (ids == NULL || !g_hash_table_lookup_extended(ids, GINT_TO_POINTER(ret), &origkey, &id))
			ret = NULL;
	}

	return ret;
}

static void gh_uniq_destroy(gpointer key, gpointer value)
{
        g_hash_table_remove(uniqids, value);
}

static void gh_uniq_destroy_str(gpointer key, gpointer value)
{
        g_hash_table_remove(uniqstrids, value);
        g_free(key);
}

/* Destroy unique IDs from `module'. This function is automatically called
   when module is destroyed with module's name as the parameter. */
void module_uniq_destroy(const char *module)
{
	GHashTable *ids;
	gpointer key;

	if (g_hash_table_lookup_extended(idlookup, module, &key, (gpointer *) &ids)) {
		g_hash_table_remove(idlookup, key);
		g_free(key);

		g_hash_table_foreach(ids, (GHFunc) gh_uniq_destroy, NULL);
		g_hash_table_destroy(ids);
	}

	if (g_hash_table_lookup_extended(stridlookup, module, &key, (gpointer *) &ids)) {
		g_hash_table_remove(stridlookup, key);
		g_free(key);

		g_hash_table_foreach(ids, (GHFunc) gh_uniq_destroy_str, NULL);
		g_hash_table_destroy(ids);
	}
}

void modules_init(void)
{
	idlookup = g_hash_table_new((GHashFunc) g_str_hash, (GCompareFunc) g_str_equal);
	uniqids = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);

	stridlookup = g_hash_table_new((GHashFunc) g_str_hash, (GCompareFunc) g_str_equal);
	uniqstrids = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);
	next_uniq_id = 0;
}

void modules_deinit(void)
{
	g_hash_table_foreach(idlookup, (GHFunc) module_uniq_destroy, NULL);
	g_hash_table_destroy(idlookup);
	g_hash_table_destroy(uniqids);

	g_hash_table_foreach(stridlookup, (GHFunc) module_uniq_destroy, NULL);
	g_hash_table_destroy(stridlookup);
	g_hash_table_destroy(uniqstrids);
}
