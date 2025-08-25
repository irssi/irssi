/*
 misc.c : irssi

    Copyright (C) 1999 Timo Sirainen

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
#include <irssi/src/core/misc.h>
#include <irssi/src/core/commands.h>

typedef struct {
	int condition;
	GInputFunction function;
        void *data;
} IRSSI_INPUT_REC;

static int irssi_io_invoke(GIOChannel *source, GIOCondition condition,
			   void *data)
{
	IRSSI_INPUT_REC *rec = data;
	int icond = 0;

	if (condition & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		/* error, we have to call the function.. */
		if (rec->condition & G_IO_IN)
			icond |= I_INPUT_READ;
		else
			icond |= I_INPUT_WRITE;
	}

	if (condition & (G_IO_IN | G_IO_PRI))
		icond |= I_INPUT_READ;
	if (condition & G_IO_OUT)
		icond |= I_INPUT_WRITE;

	if (rec->condition & icond)
		rec->function(rec->data, source, icond);

	return TRUE;
}

int i_input_add_full(GIOChannel *source, int priority, int condition, GInputFunction function,
                     void *data)
{
        IRSSI_INPUT_REC *rec;
	unsigned int result;
	GIOCondition cond;

	rec = g_new(IRSSI_INPUT_REC, 1);
	rec->condition = condition;
	rec->function = function;
	rec->data = data;

	cond = (GIOCondition) (G_IO_ERR|G_IO_HUP|G_IO_NVAL);
	if (condition & I_INPUT_READ)
		cond |= G_IO_IN|G_IO_PRI;
	if (condition & I_INPUT_WRITE)
		cond |= G_IO_OUT;

	result = g_io_add_watch_full(source, priority, cond,
				     irssi_io_invoke, rec, g_free);

	return result;
}

int i_input_add(GIOChannel *source, int condition, GInputFunction function, void *data)
{
	return i_input_add_full(source, G_PRIORITY_DEFAULT, condition, function, data);
}

/* easy way to bypass glib polling of io channel internal buffer */
int i_input_add_poll(int fd, int priority, int condition, GInputFunction function, void *data)
{
	GIOChannel *source = g_io_channel_unix_new(fd);
	int ret = i_input_add_full(source, priority, condition, function, data);
	g_io_channel_unref(source);
	return ret;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
int g_timeval_cmp(const GTimeVal *tv1, const GTimeVal *tv2)
{
	if (tv1->tv_sec < tv2->tv_sec)
		return -1;
	if (tv1->tv_sec > tv2->tv_sec)
		return 1;

	return tv1->tv_usec < tv2->tv_usec ? -1 :
		tv1->tv_usec > tv2->tv_usec ? 1 : 0;
}

long get_timeval_diff(const GTimeVal *tv1, const GTimeVal *tv2)
{
	long secs, usecs;

	secs = tv1->tv_sec - tv2->tv_sec;
	usecs = tv1->tv_usec - tv2->tv_usec;
	if (usecs < 0) {
		usecs += 1000000;
		secs--;
	}
	usecs = usecs/1000 + secs * 1000;

	return usecs;
}
#pragma GCC diagnostic pop

#if GLIB_CHECK_VERSION(2, 56, 0)
/* nothing */
#else
/* compatibility code for old GLib */
GDateTime *g_date_time_new_from_iso8601(const gchar *iso_date, GTimeZone *default_tz)
{
	GTimeVal time;
	if (g_time_val_from_iso8601(iso_date, &time)) {
		return g_date_time_new_from_timeval_utc(&time);
	} else {
		return NULL;
	}
}
#endif

#if GLIB_CHECK_VERSION(2, 76, 0)
/* nothing */
#else
gchar *g_string_free_and_steal(GString *string)
{
	return g_string_free(string, FALSE);
}
#endif

int find_substr(const char *list, const char *item)
{
	const char *ptr;

	g_return_val_if_fail(list != NULL, FALSE);
	g_return_val_if_fail(item != NULL, FALSE);

	if (*item == '\0')
		return FALSE;

	for (;;) {
		while (i_isspace(*list)) list++;
		if (*list == '\0') break;

		ptr = strchr(list, ' ');
		if (ptr == NULL) ptr = list+strlen(list);

		if (g_ascii_strncasecmp(list, item, ptr-list) == 0 &&
		    item[ptr-list] == '\0')
			return TRUE;

		list = ptr;
	}

	return FALSE;
}

int strarray_find(char **array, const char *item)
{
	char **tmp;
	int index;

	g_return_val_if_fail(array != NULL, -1);
	g_return_val_if_fail(item != NULL, -1);

	index = 0;
	for (tmp = array; *tmp != NULL; tmp++, index++) {
		if (g_ascii_strcasecmp(*tmp, item) == 0)
			return index;
	}

	return -1;
}

GSList *i_slist_find_string(GSList *list, const char *key)
{
	for (; list != NULL; list = list->next)
		if (g_strcmp0(list->data, key) == 0) return list;

	return NULL;
}

GSList *i_slist_find_icase_string(GSList *list, const char *key)
{
	for (; list != NULL; list = list->next)
		if (g_ascii_strcasecmp(list->data, key) == 0) return list;

	return NULL;
}

void *i_slist_foreach_find(GSList *list, FOREACH_FIND_FUNC func, const void *data)
{
	void *ret;

	while (list != NULL) {
		ret = func(list->data, (void *) data);
                if (ret != NULL) return ret;

		list = list->next;
	}

	return NULL;
}

void i_slist_free_full(GSList *list, GDestroyNotify free_func)
{
	GSList *tmp;

	if (list == NULL)
		return;

	for (tmp = list; tmp != NULL; tmp = tmp->next)
		free_func(tmp->data);

	g_slist_free(list);
}

GSList *i_slist_remove_string(GSList *list, const char *str)
{
	GSList *l;

	l = g_slist_find_custom(list, str, (GCompareFunc) g_strcmp0);
	if (l != NULL)
		return g_slist_remove_link(list, l);

	return list;
}

GSList *i_slist_delete_string(GSList *list, const char *str, GDestroyNotify free_func)
{
	GSList *l;

	l = g_slist_find_custom(list, str, (GCompareFunc) g_strcmp0);
	if (l != NULL) {
		free_func(l->data);
		return g_slist_delete_link(list, l);
	}

	return list;
}

/* `list' contains pointer to structure with a char* to string. */
char *gslistptr_to_string(GSList *list, int offset, const char *delimiter)
{
	GString *str;
	char **data, *ret;

	str = g_string_new(NULL);
	while (list != NULL) {
		data = G_STRUCT_MEMBER_P(list->data, offset);

		if (str->len != 0) g_string_append(str, delimiter);
		g_string_append(str, *data);
		list = list->next;
	}

	ret = g_string_free_and_steal(str);
	return ret;
}

/* `list' contains char* */
char *i_slist_to_string(GSList *list, const char *delimiter)
{
	GString *str;
	char *ret;

	str = g_string_new(NULL);
	while (list != NULL) {
		if (str->len != 0) g_string_append(str, delimiter);
		g_string_append(str, list->data);

		list = list->next;
	}

	ret = g_string_free_and_steal(str);
	return ret;
}

/* remove all the options from the optlist hash table that are valid for the
 * command cmd */
GList *optlist_remove_known(const char *cmd, GHashTable *optlist)
{
	GList *list, *tmp, *next;

	list = g_hash_table_get_keys(optlist);
	if (cmd != NULL && list != NULL) {
		for (tmp = list; tmp != NULL; tmp = next) {
			char *option = tmp->data;
			next = tmp->next;

			if (command_have_option(cmd, option))
				list = g_list_remove(list, option);
		}
	}

	return list;
}

GList *i_list_find_string(GList *list, const char *key)
{
	for (; list != NULL; list = list->next)
		if (g_strcmp0(list->data, key) == 0) return list;

	return NULL;
}

GList *i_list_find_icase_string(GList *list, const char *key)
{
	for (; list != NULL; list = list->next)
		if (g_ascii_strcasecmp(list->data, key) == 0) return list;

	return NULL;
}

char *stristr(const char *data, const char *key)
{
	const char *max;
	int keylen, datalen, pos;

	keylen = strlen(key);
	datalen = strlen(data);

	if (keylen > datalen)
		return NULL;
	if (keylen == 0)
		return (char *) data;

	max = data+datalen-keylen;
	pos = 0;
	while (data <= max) {
		if (key[pos] == '\0')
                        return (char *) data;

		if (i_toupper(data[pos]) == i_toupper(key[pos]))
			pos++;
		else {
			data++;
                        pos = 0;
		}
	}

	return NULL;
}

#define isbound(c) \
	((unsigned char) (c) < 128 && \
	(i_isspace(c) || i_ispunct(c)))

static char *strstr_full_case(const char *data, const char *key, int icase)
{
	const char *start, *max;
	int keylen, datalen, pos, match;

	keylen = strlen(key);
	datalen = strlen(data);

	if (keylen > datalen)
		return NULL;
	if (keylen == 0)
		return (char *) data;

	max = data+datalen-keylen;
	start = data; pos = 0;
	while (data <= max) {
		if (key[pos] == '\0') {
			if (data[pos] != '\0' && !isbound(data[pos])) {
				data++;
				pos = 0;
                                continue;
			}
			return (char *) data;
		}

		match = icase ? (i_toupper(data[pos]) == i_toupper(key[pos])) :
				 data[pos] == key[pos];

		if (match && (pos != 0 || data == start || isbound(data[-1])))
			pos++;
		else {
			data++;
                        pos = 0;
		}
	}

	return NULL;
}

char *strstr_full(const char *data, const char *key)
{
        return strstr_full_case(data, key, FALSE);
}

char *stristr_full(const char *data, const char *key)
{
        return strstr_full_case(data, key, TRUE);
}

/* convert ~/ to $HOME */
char *convert_home(const char *path)
{
	const char *home;

	if (*path == '~' && (*(path+1) == '/' || *(path+1) == '\0')) {
		home = g_get_home_dir();
		if (home == NULL)
			home = ".";

		return g_strconcat(home, path+1, NULL);
	} else {
		return g_strdup(path);
	}
}

int i_istr_equal(gconstpointer v, gconstpointer v2)
{
	return g_ascii_strcasecmp((const char *) v, (const char *) v2) == 0;
}

int i_istr_cmp(gconstpointer v, gconstpointer v2)
{
	return g_ascii_strcasecmp((const char *) v, (const char *) v2);
}

guint i_istr_hash(gconstpointer v)
{
	const signed char *p;
	guint32 h = 5381;

	for (p = v; *p != '\0'; p++)
		h = (h << 5) + h + g_ascii_toupper(*p);

	return h;
}

/* Find `mask' from `data', you can use * and ? wildcards. */
int match_wildcards(const char *cmask, const char *data)
{
	char *mask, *newmask, *p1, *p2;
	int ret;

	newmask = mask = g_strdup(cmask);
	for (; *mask != '\0' && *data != '\0'; mask++) {
		if (*mask != '*') {
			if (*mask != '?' && i_toupper(*mask) != i_toupper(*data))
				break;

			data++;
			continue;
		}

		while (*mask == '?' || *mask == '*') mask++;
		if (*mask == '\0') {
			data += strlen(data);
			break;
		}

		p1 = strchr(mask, '*');
		p2 = strchr(mask, '?');
		if (p1 == NULL || (p2 < p1 && p2 != NULL)) p1 = p2;

		if (p1 != NULL) *p1 = '\0';

		data = stristr(data, mask);
		if (data == NULL) break;

		data += strlen(mask);
		mask += strlen(mask)-1;

		if (p1 != NULL) *p1 = p1 == p2 ? '?' : '*';
	}

	while (*mask == '*') mask++;

	ret = data != NULL && *data == '\0' && *mask == '\0';
	g_free(newmask);

	return ret;
}

/* Return TRUE if all characters in `str' are numbers.
   Stop when `end_char' is found from string. */
int is_numeric(const char *str, char end_char)
{
	g_return_val_if_fail(str != NULL, FALSE);

	if (*str == '\0' || *str == end_char)
		return FALSE;

	while (*str != '\0' && *str != end_char) {
		if (!i_isdigit(*str)) return FALSE;
		str++;
	}

	return TRUE;
}

/* replace all `from' chars in string to `to' chars. returns `str' */
char *replace_chars(char *str, char from, char to)
{
	char *p;

	for (p = str; *p != '\0'; p++) {
		if (*p == from) *p = to;
	}
	return str;
}

int octal2dec(int octal)
{
	int dec, n;

	dec = 0; n = 1;
	while (octal != 0) {
		dec += n*(octal%10);
		octal /= 10; n *= 8;
	}

	return dec;
}

int dec2octal(int decimal)
{
	int octal, pos;

	octal = 0; pos = 0;
	while (decimal > 0) {
		octal += (decimal & 7)*(pos == 0 ? 1 : pos);
		decimal /= 8;
		pos += 10;
	}

	return octal;
}

/* string -> uoff_t */
uoff_t str_to_uofft(const char *str)
{
#ifdef UOFF_T_LONG_LONG
	return (uoff_t)strtoull(str, NULL, 10);
#else
	return (uoff_t)strtoul(str, NULL, 10);
#endif
}

/* convert all low-ascii (<32) to ^<A..> combinations */
char *show_lowascii(const char *str)
{
	char *ret, *p;

	ret = p = g_malloc(strlen(str)*2+1);
	while (*str != '\0') {
		if ((unsigned char) *str >= 32)
			*p++ = *str;
		else {
			*p++ = '^';
			*p++ = *str + 'A'-1;
		}
		str++;
	}
	*p = '\0';

	return ret;
}

/* Get time in human readable form with localtime() + asctime() */
char *my_asctime(time_t t)
{
	struct tm *tm;
	char *str;
        int len;

	tm = localtime(&t);
	if (tm == NULL)
	    return g_strdup("???");

	str = g_strdup(asctime(tm));

	len = strlen(str);
	if (len > 0) str[len-1] = '\0';
        return str;
}

/* Returns number of columns needed to print items.
   save_column_widths is filled with length of each column. */
int get_max_column_count(GSList *items, COLUMN_LEN_FUNC len_func,
			 int max_width, int max_columns,
			 int item_extra, int item_min_size,
			 int **save_column_widths, int *rows)
{
        GSList *tmp;
	int **columns, *columns_width, *columns_rows;
	int item_pos, items_count;
	int ret, len, max_len, n, col;

	items_count = g_slist_length(items);
	if (items_count == 0) {
		*save_column_widths = NULL;
                *rows = 0;
		return 0;
	}

	len = max_width/(item_extra+item_min_size);
        if (len <= 0) len = 1;
	if (max_columns <= 0 || len < max_columns)
                max_columns = len;

	columns = g_new0(int *, max_columns);
	columns_width = g_new0(int, max_columns);
	columns_rows = g_new0(int, max_columns);

	for (n = 1; n < max_columns; n++) {
		columns[n] = g_new0(int, n+1);
		columns_rows[n] = items_count <= n+1 ? 1 :
                        (items_count+n)/(n+1);
	}

	/* for each possible column count, save the column widths and
	   find the biggest column count that fits to screen. */
        item_pos = 0; max_len = 0;
	for (tmp = items; tmp != NULL; tmp = tmp->next) {
		len = item_extra+len_func(tmp->data);
		if (max_len < len)
			max_len = len;

		for (n = 1; n < max_columns; n++) {
			if (columns_width[n] > max_width)
				continue; /* too wide */

			col = item_pos/columns_rows[n];
			if (columns[n][col] < len) {
				columns_width[n] += len-columns[n][col];
                                columns[n][col] = len;
			}
		}

                item_pos++;
	}

	for (n = max_columns-1; n >= 1; n--) {
		if (columns_width[n] <= max_width &&
		    columns[n][n] > 0)
                        break;
	}
        ret = n+1;

	*save_column_widths = g_new(int, ret);
	if (ret == 1) {
                **save_column_widths = max_len;
                *rows = 1;
	} else {
		memcpy(*save_column_widths, columns[ret-1], sizeof(int)*ret);
		*rows = columns_rows[ret-1];
	}

	for (n = 1; n < max_columns; n++)
                g_free(columns[n]);
	g_free(columns_width);
	g_free(columns_rows);
	g_free(columns);

        return ret;
}

/* Return a column sorted copy of a list. */
GSList *columns_sort_list(GSList *list, int rows)
{
        GSList *tmp, *sorted;
	int row, skip;

	if (list == NULL || rows == 0)
                return list;

	sorted = NULL;

	for (row = 0; row < rows; row++) {
                tmp = g_slist_nth(list, row);
                skip = 1;
		for (; tmp != NULL; tmp = tmp->next) {
			if (--skip == 0) {
                                skip = rows;
				sorted = g_slist_append(sorted, tmp->data);
			}
		}
	}

	g_return_val_if_fail(g_slist_length(sorted) ==
			     g_slist_length(list), sorted);
        return sorted;
}

/* Expand escape string, the first character in data should be the
   one after '\'. Returns the expanded character or -1 if error. */
int expand_escape(const char **data)
{
        char digit[4];

	switch (**data) {
	case 't':
		return '\t';
	case 'r':
		return '\r';
	case 'n':
		return '\n';
	case 'e':
		return 27; /* ESC */
	case '\\':
		return '\\';

	case 'x':
                /* hex digit */
		if (!i_isxdigit((*data)[1]) || !i_isxdigit((*data)[2]))
			return -1;

		digit[0] = (*data)[1];
		digit[1] = (*data)[2];
                digit[2] = '\0';
		*data += 2;
		return strtol(digit, NULL, 16);
	case 'c':
		/* check for end of string */
		if ((*data)[1] == '\0')
			return 0;
		/* control character (\cA = ^A) */
		(*data)++;
		return i_toupper(**data) - 64;
	case '0': case '1': case '2': case '3':
	case '4': case '5': case '6': case '7':
                /* octal */
		digit[1] = digit[2] = digit[3] = '\0';
                digit[0] = (*data)[0];
		if ((*data)[1] >= '0' && (*data)[1] <= '7') {
			++*data;
			digit[1] = **data;
			if ((*data)[1] >= '0' && (*data)[1] <= '7') {
				++*data;
				digit[2] = **data;
			}
		}
		return strtol(digit, NULL, 8);
	default:
		return -1;
	}
}

/* Escape all '"', "'" and '\' chars with '\' */
char *escape_string(const char *str)
{
	char *ret, *p;

	p = ret = g_malloc(strlen(str)*2+1);
	while (*str != '\0') {
		if (*str == '"' || *str == '\'' || *str == '\\')
			*p++ = '\\';
		*p++ = *str++;
	}
	*p = '\0';

	return ret;
}

/* Escape all '\' chars with '\' */
char *escape_string_backslashes(const char *str)
{
	char *ret, *p;

	p = ret = g_malloc(strlen(str)*2+1);
	while (*str != '\0') {
		if (*str == '\\')
			*p++ = '\\';
		*p++ = *str++;
	}
	*p = '\0';

	return ret;
}

int nearest_power(int num)
{
	int n = 1;

	while (n < num) n <<= 1;
	return n;
}

/* Parses unsigned integers from strings with decent error checking.
 * Returns true on success, false otherwise (overflow, no valid number, etc)
 * There's a 31 bit limit so the output can be assigned to signed positive ints */
int parse_uint(const char *nptr, char **endptr, int base, guint *number)
{
	char *endptr_;
	gulong parsed;

	/* strtoul accepts whitespace and plus/minus signs, for some reason */
	if (!i_isdigit(*nptr)) {
		return FALSE;
	}

	errno = 0;
	parsed = strtoul(nptr, &endptr_, base);

	if (errno || endptr_ == nptr || parsed >= (1U << 31)) {
		return FALSE;
	}

	if (endptr) {
		*endptr = endptr_;
	}

	if (number) {
		*number = (guint) parsed;
	}

	return TRUE;
}

static int parse_number_sign(const char *input, char **endptr, int *sign)
{
	int sign_ = 1;

	while (i_isspace(*input))
		input++;

	if (*input == '-') {
		sign_ = -sign_;
		input++;
	}

	*sign = sign_;
	*endptr = (char *) input;
	return TRUE;
}

static int parse_time_interval_uint(const char *time, guint *msecs)
{
	const char *desc;
	guint number;
	int len, ret, digits;

	*msecs = 0;

	/* max. return value is around 24 days */
	number = 0; ret = TRUE; digits = FALSE;
	while (i_isspace(*time))
		time++;
	for (;;) {
		if (i_isdigit(*time)) {
			char *endptr;
			if (!parse_uint(time, &endptr, 10, &number)) {
				return FALSE;
			}
			time = endptr;
			digits = TRUE;
			continue;
		}

		if (!digits)
			return FALSE;

		/* skip punctuation */
		while (*time != '\0' && i_ispunct(*time) && *time != '-')
			time++;

		/* get description */
		for (len = 0, desc = time; i_isalpha(*time); time++)
			len++;

		while (i_isspace(*time))
			time++;

		if (len == 0) {
			if (*time != '\0')
				return FALSE;
			*msecs += number * 1000; /* assume seconds */
			return TRUE;
		}

		if (g_ascii_strncasecmp(desc, "days", len) == 0) {
			if (number > 24) {
				/* would overflow */
				return FALSE;
			}
			*msecs += number * 1000*3600*24;
		} else if (g_ascii_strncasecmp(desc, "hours", len) == 0)
			*msecs += number * 1000*3600;
		else if (g_ascii_strncasecmp(desc, "minutes", len) == 0 ||
			 g_ascii_strncasecmp(desc, "mins", len) == 0)
			*msecs += number * 1000*60;
		else if (g_ascii_strncasecmp(desc, "seconds", len) == 0 ||
			 g_ascii_strncasecmp(desc, "secs", len) == 0)
			*msecs += number * 1000;
		else if (g_ascii_strncasecmp(desc, "milliseconds", len) == 0 ||
			 g_ascii_strncasecmp(desc, "millisecs", len) == 0 ||
			 g_ascii_strncasecmp(desc, "mseconds", len) == 0 ||
			 g_ascii_strncasecmp(desc, "msecs", len) == 0)
			*msecs += number;
		else {
			ret = FALSE;
		}

		/* skip punctuation */
		while (*time != '\0' && i_ispunct(*time) && *time != '-')
			time++;

		if (*time == '\0')
			break;

		number = 0;
		digits = FALSE;
	}

	return ret;
}

static int parse_size_uint(const char *size, guint *bytes)
{
	const char *desc;
	guint number, multiplier, limit;
	int len;

	*bytes = 0;

	/* max. return value is about 1.6 years */
	number = 0;
	while (*size != '\0') {
		if (i_isdigit(*size)) {
			char *endptr;
			if (!parse_uint(size, &endptr, 10, &number)) {
				return FALSE;
			}
			size = endptr;
			continue;
		}

		/* skip punctuation */
		while (*size != '\0' && i_ispunct(*size))
			size++;

		/* get description */
		for (len = 0, desc = size; i_isalpha(*size); size++)
			len++;

		if (len == 0) {
			if (number == 0) {
				/* "0" - allow it */
				return TRUE;
			}

			*bytes += number*1024; /* assume kilobytes */
			return FALSE;
		}

		multiplier = 0;
		limit = 0;

		if (g_ascii_strncasecmp(desc, "gbytes", len) == 0) {
			multiplier = 1U << 30;
			limit = 2U << 0;
		}
		if (g_ascii_strncasecmp(desc, "mbytes", len) == 0) {
			multiplier = 1U << 20;
			limit = 2U << 10;
		}
		if (g_ascii_strncasecmp(desc, "kbytes", len) == 0) {
			multiplier = 1U << 10;
			limit = 2U << 20;
		}
		if (g_ascii_strncasecmp(desc, "bytes", len) == 0) {
			multiplier = 1;
			limit = 2U << 30;
		}

		if (limit && number > limit) {
			return FALSE;
		}

		*bytes += number * multiplier;

		/* skip punctuation */
		while (*size != '\0' && i_ispunct(*size))
			size++;
	}

	return TRUE;
}

int parse_size(const char *size, int *bytes)
{
	guint bytes_;
	int ret;

	ret = parse_size_uint(size, &bytes_);

	if (bytes_ > (1U << 31)) {
		return FALSE;
	}

	*bytes = bytes_;
	return ret;
}

int parse_time_interval(const char *time, int *msecs)
{
	guint msecs_;
	char *number;
	int ret, sign;

	parse_number_sign(time, &number, &sign);

	ret = parse_time_interval_uint(number, &msecs_);

	if (msecs_ > (1U << 31)) {
		return FALSE;
	}

	*msecs = msecs_ * sign;
	return ret;
}


char *ascii_strup(char *str)
{
	char *s;

	for (s = str; *s; s++)
		*s = g_ascii_toupper (*s);
	return str;
}

char *ascii_strdown(char *str)
{
	char *s;

	for (s = str; *s; s++)
		*s = g_ascii_tolower (*s);
	return str;
}

char **strsplit_len(const char *str, int len, gboolean onspace)
{
	char **ret = g_new(char *, 1);
	int n;
	int offset;

	for (n = 0; *str != '\0'; n++, str += offset) {
		offset = MIN(len, strlen(str));
		if (onspace && strlen(str) > len) {
			/*
			 * Try to find a space to split on and leave
			 * the space on the previous line.
			 */
			int i;
			for (i = len - 1; i > 0; i--) {
				if (str[i] == ' ') {
					offset = i;
					break;
				}
			}
		}
		ret[n] = g_strndup(str, offset);
		ret = g_renew(char *, ret, n + 2);
	}
	ret[n] = NULL;

	return ret;
}

char *binary_to_hex(unsigned char *buffer, size_t size)
{
	static const char hex[] = "0123456789ABCDEF";
	char *result = NULL;
	int i;

	if (buffer == NULL || size == 0)
		return NULL;

	result = g_malloc(3 * size);

	for (i = 0; i < size; i++) {
		result[i * 3 + 0] = hex[(buffer[i] >> 4) & 0xf];
		result[i * 3 + 1] = hex[(buffer[i] >> 0) & 0xf];
		result[i * 3 + 2] = i == size - 1 ? '\0' : ':';
	}

	return result;
}
