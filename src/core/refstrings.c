#include <glib.h>
#include <string.h>

#include <irssi/src/core/refstrings.h>

#if GLIB_CHECK_VERSION(2, 58, 0)

void i_refstr_init(void)
{
	/* nothing */
}

char *i_refstr_intern(const char *str)
{
	if (str == NULL) {
		return NULL;
	}

	return g_ref_string_new_intern(str);
}

void i_refstr_release(char *str)
{
	if (str == NULL) {
		return;
	}

	g_ref_string_release(str);
}

void i_refstr_deinit(void)
{
	/* nothing */
}

char *i_refstr_table_size_info(void)
{
	/* not available */
	return NULL;
}

#else

GHashTable *i_refstr_table;

void i_refstr_init(void)
{
	i_refstr_table = g_hash_table_new(g_str_hash, g_str_equal);
}

char *i_refstr_intern(const char *str)
{
	char *ret;
	gpointer rc_p, ret_p;
	size_t rc;

	if (str == NULL)
		return NULL;

	if (g_hash_table_lookup_extended(i_refstr_table, str, &ret_p, &rc_p)) {
		rc = GPOINTER_TO_SIZE(rc_p);
		ret = ret_p;
	} else {
		rc = 0;
		ret = g_strdup(str);
	}

	if (rc + 1 <= G_MAXSIZE) {
		g_hash_table_insert(i_refstr_table, ret, GSIZE_TO_POINTER(rc + 1));
		return ret;
	} else {
		return g_strdup(str);
	}
}

void i_refstr_release(char *str)
{
	char *ret;
	gpointer rc_p, ret_p;
	size_t rc;

	if (str == NULL)
		return;

	if (g_hash_table_lookup_extended(i_refstr_table, str, &ret_p, &rc_p)) {
		rc = GPOINTER_TO_SIZE(rc_p);
		ret = ret_p;
	} else {
		rc = 0;
		ret = NULL;
	}

	if (ret == str) {
		if (rc > 1) {
			g_hash_table_insert(i_refstr_table, ret, GSIZE_TO_POINTER(rc - 1));
		} else {
			g_hash_table_remove(i_refstr_table, ret);
			g_free(ret);
		}
	} else {
		g_free(str);
	}
}

void i_refstr_deinit(void)
{
	g_hash_table_foreach(i_refstr_table, (GHFunc) g_free, NULL);
	g_hash_table_destroy(i_refstr_table);
}

char *i_refstr_table_size_info(void)
{
	GHashTableIter iter;
	void *k_p, *v_p;
	size_t count, mem;
	count = 0;
	mem = 0;
	g_hash_table_iter_init(&iter, i_refstr_table);
	while (g_hash_table_iter_next(&iter, &k_p, &v_p)) {
		char *key = k_p;
		count++;
		mem += sizeof(char) * (strlen(key) + 1) + 2 * sizeof(void *);
	}

	return g_strdup_printf("Shared strings: %ld, %dkB of data", count,
	          (int) (mem / 1024));
}

#endif
