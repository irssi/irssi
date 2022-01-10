#ifndef IRSSI_CORE_MISC_H
#define IRSSI_CORE_MISC_H

int i_input_add_poll(int fd, int priority, int condition, GInputFunction function, void *data);

/* `str' should be type char[MAX_INT_STRLEN] */
#define ltoa(str, num) \
	g_snprintf(str, sizeof(str), "%d", num)

typedef void* (*FOREACH_FIND_FUNC) (void *item, void *data);
typedef int (*COLUMN_LEN_FUNC)(void *data);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
/* Returns 1 if tv1 > tv2, -1 if tv2 > tv1 or 0 if they're equal. */
int g_timeval_cmp(const GTimeVal *tv1, const GTimeVal *tv2) G_GNUC_DEPRECATED;
/* Returns "tv1 - tv2", returns the result in milliseconds. Note that
   if the difference is too large, the result might be invalid. */
long get_timeval_diff(const GTimeVal *tv1, const GTimeVal *tv2) G_GNUC_DEPRECATED;
#pragma GCC diagnostic pop

#if GLIB_CHECK_VERSION(2, 56, 0)
/* nothing */
#else
/* compatibility code for old GLib */
GDateTime *g_date_time_new_from_iso8601(const gchar *iso_date, GTimeZone *default_tz);
#endif

GSList *i_slist_find_string(GSList *list, const char *key);
GSList *i_slist_find_icase_string(GSList *list, const char *key);
GList *i_list_find_string(GList *list, const char *key);
GList *i_list_find_icase_string(GList *list, const char *key);
GSList *i_slist_remove_string(GSList *list, const char *str) G_GNUC_DEPRECATED;
GSList *i_slist_delete_string(GSList *list, const char *str, GDestroyNotify free_func);

void i_slist_free_full(GSList *list, GDestroyNotify free_func);

void *i_slist_foreach_find(GSList *list, FOREACH_FIND_FUNC func, const void *data);

/* `list' contains pointer to structure with a char* to string. */
char *gslistptr_to_string(GSList *list, int offset, const char *delimiter);
/* `list' contains char* */
char *i_slist_to_string(GSList *list, const char *delimiter);

GList *optlist_remove_known(const char *cmd, GHashTable *optlist);

/* convert ~/ to $HOME */
char *convert_home(const char *path);

/* Case-insensitive string hash functions */
int i_istr_equal(gconstpointer v, gconstpointer v2);
unsigned int i_istr_hash(gconstpointer v);

/* Case-insensitive GCompareFunc func */
int i_istr_cmp(gconstpointer v, gconstpointer v2);

/* Find `mask' from `data', you can use * and ? wildcards. */
int match_wildcards(const char *mask, const char *data);

/* octal <-> decimal conversions */
int octal2dec(int octal);
int dec2octal(int decimal) G_GNUC_DEPRECATED;

/* Get time in human readable form with localtime() + asctime() */
char *my_asctime(time_t t);

/* Returns number of columns needed to print items.
   save_column_widths is filled with length of each column. */
int get_max_column_count(GSList *items, COLUMN_LEN_FUNC len_func,
			 int max_width, int max_columns,
			 int item_extra, int item_min_size,
			 int **save_column_widths, int *rows);

/* Return a column sorted copy of a list. */
GSList *columns_sort_list(GSList *list, int rows);

/* Expand escape string, the first character in data should be the
   one after '\'. Returns the expanded character or -1 if error. */
int expand_escape(const char **data);

int nearest_power(int num);

/* Returns TRUE / FALSE */
int parse_uint(const char *nptr, char **endptr, int base, guint *number);
int parse_time_interval(const char *time, int *msecs);
int parse_size(const char *size, int *bytes);

/* Return TRUE if all characters in `str' are numbers.
   Stop when `end_char' is found from string. */
int is_numeric(const char *str, char end_char);

/* strstr() with case-ignoring */
char *stristr(const char *data, const char *key);

/* like strstr(), but matches only for full words. */
char *strstr_full(const char *data, const char *key);
char *stristr_full(const char *data, const char *key);

char *ascii_strup(char *str);
char *ascii_strdown(char *str);

/* Escape all '"', "'" and '\' chars with '\' */
char *escape_string(const char *str);

/* Escape all '\' chars with '\' */
char *escape_string_backslashes(const char *str);

/* convert all low-ascii (<32) to ^<A..> combinations */
char *show_lowascii(const char *str);

/* replace all `from' chars in string to `to' chars. returns `str' */
char *replace_chars(char *str, char from, char to);

/* return index of `item' in `array' or -1 if not found */
int strarray_find(char **array, const char *item);

/* string -> uoff_t */
uoff_t str_to_uofft(const char *str);

/* find `item' from a space separated `list' */
int find_substr(const char *list, const char *item);

/* split `str' into `len' sized substrings */
char **strsplit_len(const char *str, int len, gboolean onspace);

/* Convert a given buffer to a printable, colon-delimited, hex string and
 * return a pointer to the newly allocated buffer */
char *binary_to_hex(unsigned char *buffer, size_t size);

#endif
