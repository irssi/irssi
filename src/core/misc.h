#ifndef __MISC_H
#define __MISC_H

/* `str' should be type char[MAX_INT_STRLEN] */
#define ltoa(str, num) \
	g_snprintf(str, sizeof(str), "%d", num)

typedef void* (*FOREACH_FIND_FUNC) (void *item, void *data);

long get_timeval_diff(const GTimeVal *tv1, const GTimeVal *tv2);

/* find `item' from a space separated `list' */
int find_substr(const char *list, const char *item);
/* return how many items `array' has */
int strarray_length(char **array);
/* return index of `item' in `array' or -1 if not found */
int strarray_find(char **array, const char *item);

int copyfile(const char *src, const char *dest);
int execute(const char *cmd); /* returns pid or -1 = error */

GSList *gslist_find_string(GSList *list, const char *key);
GSList *gslist_find_icase_string(GSList *list, const char *key);
GList *glist_find_string(GList *list, const char *key);
GList *glist_find_icase_string(GList *list, const char *key);

void *gslist_foreach_find(GSList *list, FOREACH_FIND_FUNC func, void *data);
char *gslist_to_string(GSList *list, int offset, const char *delimiter);

/* strstr() with case-ignoring */
char *stristr(const char *data, const char *key);
/* stristr(), but matches only for full words */
char *stristr_full(const char *data, const char *key);
/* easy way to check if regexp matches */
int regexp_match(const char *str, const char *regexp);

char *convert_home(const char *path);

/* Case-insensitive string hash functions */
int g_istr_equal(gconstpointer v, gconstpointer v2);
unsigned int g_istr_hash(gconstpointer v);

/* Find `mask' from `data', you can use * and ? wildcards. */
int match_wildcards(const char *mask, const char *data);

/* Return TRUE if all characters in `str' are numbers.
   Stop when `end_char' is found from string. */
int is_numeric(const char *str, char end_char);

/* replace all `from' chars in string to `to' chars. returns `str' */
char *replace_chars(char *str, char from, char to);

/* octal <-> decimal conversions */
int octal2dec(int octal);
int dec2octal(int decimal);

#endif
