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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "misc.h"
#include "pidwait.h"

#include <errno.h>
#ifdef HAVE_REGEX_H
#  include <regex.h>
#endif

typedef struct {
	GInputCondition condition;
	GInputFunction function;
        void *data;
} IRSSI_INPUT_REC;

static int irssi_io_invoke(GIOChannel *source, GIOCondition condition,
			   void *data)
{
	IRSSI_INPUT_REC *rec = data;
	GInputCondition icond = 0;

	if (condition & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		/* error, we have to call the function.. */
		if (rec->condition & G_IO_IN)
			icond |= G_INPUT_READ;
		else
			icond |= G_INPUT_WRITE;
	}

	if (condition & (G_IO_IN | G_IO_PRI))
		icond |= G_INPUT_READ;
	if (condition & G_IO_OUT)
		icond |= G_INPUT_WRITE;

	if (rec->condition & icond) {
		rec->function(rec->data, g_io_channel_unix_get_fd(source),
			      icond);
	}

	return TRUE;
}

int g_input_add_full(int source, int priority, GInputCondition condition,
		     GInputFunction function, void *data)
{
        IRSSI_INPUT_REC *rec;
	unsigned int result;
	GIOChannel *channel;
	GIOCondition cond;

	rec = g_new(IRSSI_INPUT_REC, 1);
	rec->condition = condition;
	rec->function = function;
	rec->data = data;

	cond = G_IO_ERR|G_IO_HUP|G_IO_NVAL;
	if (condition & G_INPUT_READ)
		cond |= G_IO_IN|G_IO_PRI;
	if (condition & G_INPUT_WRITE)
		cond |= G_IO_OUT;

	channel = g_io_channel_unix_new (source);
	result = g_io_add_watch_full(channel, priority, cond,
				     irssi_io_invoke, rec, g_free);
	g_io_channel_unref(channel);

	return result;
}

int g_input_add(int source, GInputCondition condition,
		GInputFunction function, void *data)
{
	return g_input_add_full(source, G_PRIORITY_DEFAULT, condition,
				function, data);
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

int find_substr(const char *list, const char *item)
{
	const char *ptr;

	g_return_val_if_fail(list != NULL, FALSE);
	g_return_val_if_fail(item != NULL, FALSE);

	if (*item == '\0')
		return FALSE;

	for (;;) {
		while (isspace((gint) *list)) list++;
		if (*list == '\0') break;

		ptr = strchr(list, ' ');
		if (ptr == NULL) ptr = list+strlen(list);

		if (g_strncasecmp(list, item, ptr-list) == 0 &&
		    item[ptr-list] == '\0')
			return TRUE;

		list = ptr;
	}

	return FALSE;
}

int strarray_length(char **array)
{
	int len;

	g_return_val_if_fail(array != NULL, 0);

	len = 0;
	while (*array) {
		len++;
                array++;
	}
        return len;
}

int strarray_find(char **array, const char *item)
{
	char **tmp;
	int index;

	g_return_val_if_fail(array != NULL, 0);
	g_return_val_if_fail(item != NULL, 0);

	index = 0;
	for (tmp = array; *tmp != NULL; tmp++, index++) {
		if (g_strcasecmp(*tmp, item) == 0)
			return index;
	}

	return -1;
}

int execute(const char *cmd)
{
	char **args;
#ifndef WIN32
	int pid;
#endif

	g_return_val_if_fail(cmd != NULL, -1);

#ifndef WIN32
	pid = fork();
	if (pid == -1) return FALSE;
	if (pid != 0) {
		pidwait_add(pid);
		return pid;
	}

	args = g_strsplit(cmd, " ", -1);
	execvp(args[0], args);
	g_strfreev(args);

	_exit(99);
	return -1;
#else
	args = g_strsplit(cmd, " ", -1);
	_spawnvp(_P_DETACH, args[0], args);
	g_strfreev(args);
	return 0;
#endif
}

GSList *gslist_find_string(GSList *list, const char *key)
{
	for (list = list; list != NULL; list = list->next)
		if (strcmp(list->data, key) == 0) return list;

	return NULL;
}

GSList *gslist_find_icase_string(GSList *list, const char *key)
{
	for (list = list; list != NULL; list = list->next)
		if (g_strcasecmp(list->data, key) == 0) return list;

	return NULL;
}

void *gslist_foreach_find(GSList *list, FOREACH_FIND_FUNC func, const void *data)
{
	void *ret;

	while (list != NULL) {
		ret = func(list->data, (void *) data);
                if (ret != NULL) return ret;

		list = list->next;
	}

	return NULL;
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

        ret = str->str;
	g_string_free(str, FALSE);
	return ret;
}

/* `list' contains char* */
char *gslist_to_string(GSList *list, const char *delimiter)
{
	GString *str;
	char *ret;

	str = g_string_new(NULL);
	while (list != NULL) {
		if (str->len != 0) g_string_append(str, delimiter);
		g_string_append(str, list->data);

		list = list->next;
	}

        ret = str->str;
	g_string_free(str, FALSE);
	return ret;
}

void hash_save_key(char *key, void *value, GSList **list)
{
        *list = g_slist_append(*list, key);
}

/* save all keys in hash table to linked list - you shouldn't remove any
   items while using this list, use g_slist_free() after you're done with it */
GSList *hashtable_get_keys(GHashTable *hash)
{
	GSList *list;

	list = NULL;
	g_hash_table_foreach(hash, (GHFunc) hash_save_key, &list);
	return list;
}

GList *glist_find_string(GList *list, const char *key)
{
	for (list = list; list != NULL; list = list->next)
		if (strcmp(list->data, key) == 0) return list;

	return NULL;
}

GList *glist_find_icase_string(GList *list, const char *key)
{
	for (list = list; list != NULL; list = list->next)
		if (g_strcasecmp(list->data, key) == 0) return list;

	return NULL;
}

char *stristr(const char *data, const char *key)
{
	const char *pos, *max;
	int keylen, datalen;

	keylen = strlen(key);
	datalen = strlen(data);

	if (keylen > datalen)
		return NULL;

	max = data+datalen-keylen;
	for (pos = data; pos <= max; pos++) {
		if (g_strncasecmp(pos, key, keylen) == 0)
			return (char *) pos;
	}

	return NULL;
}

#define isbound(c) \
	((unsigned char) (c) < 128 && \
	(isspace((int) (c)) || ispunct((int) (c))))

char *stristr_full(const char *data, const char *key)
{
	const char *pos, *max;
	int keylen, datalen;

	keylen = strlen(key);
	datalen = strlen(data);

	if (keylen > datalen)
		return NULL;

	max = data+datalen-keylen;
	for (pos = data; pos <= max; pos++) {
		if (pos > data && !isbound(pos[-1])) continue;

		if (g_strncasecmp(pos, key, keylen) == 0 &&
		    (pos[keylen] == '\0' || isbound(pos[keylen])))
			return (char *) pos;
	}

	return NULL;
}

int regexp_match(const char *str, const char *regexp)
{
#ifdef HAVE_REGEX_H
	regex_t preg;
	int ret;

	if (regcomp(&preg, regexp, REG_EXTENDED|REG_ICASE|REG_NOSUB) != 0)
                return 0;

	ret = regexec(&preg, str, 0, NULL, 0);
	regfree(&preg);

	return ret == 0;
#else
	return FALSE;
#endif
}

/* Create the directory and all it's parent directories */
int mkpath(const char *path, int mode)
{
	struct stat statbuf;
	const char *p;
	char *dir;

	g_return_val_if_fail(path != NULL, -1);

	p = g_path_skip_root((char *) path);
	for (;;) {
		if (*p != G_DIR_SEPARATOR && *p != '\0') {
			p++;
			continue;
		}

		dir = g_strndup(path, (int) (p-path));
		if (stat(dir, &statbuf) != 0) {
#ifndef WIN32
			if (mkdir(dir, mode) == -1) {
#else
			if (_mkdir(dir) == -1) {
#endif
				g_free(dir);
				return -1;
			}
		}
		g_free(dir);

		if (*p++ == '\0')
			break;
	}

	return 0;
}

/* convert ~/ to $HOME */
char *convert_home(const char *path)
{
	return *path == '~' && (*(path+1) == '/' || *(path+1) == '\0') ?
		g_strconcat(g_get_home_dir(), path+1, NULL) :
		g_strdup(path);
}

int g_istr_equal(gconstpointer v, gconstpointer v2)
{
	return g_strcasecmp((const char *) v, (const char *) v2) == 0;
}

int g_istr_cmp(gconstpointer v, gconstpointer v2)
{
	return g_strcasecmp((const char *) v, (const char *) v2);
}

/* a char* hash function from ASU */
unsigned int g_istr_hash(gconstpointer v)
{
	const char *s = (const char *) v;
	unsigned int h = 0, g;

	while (*s != '\0') {
		h = (h << 4) + toupper(*s);
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		s++;
	}

	return h /* % M */;
}

/* Find `mask' from `data', you can use * and ? wildcards. */
int match_wildcards(const char *cmask, const char *data)
{
	char *mask, *newmask, *p1, *p2;
	int ret;

	newmask = mask = g_strdup(cmask);
	for (; *mask != '\0' && *data != '\0'; mask++) {
		if (*mask != '*') {
			if (*mask != '?' && toupper(*mask) != toupper(*data))
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
		if (!isdigit(*str)) return FALSE;
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

/* convert all low-ascii (<32) to ^<A..> combinations */
char *show_lowascii(const char *channel)
{
	char *str, *p;

	str = p = g_malloc(strlen(channel)*2+1);
	while (*channel != '\0') {
		if ((unsigned char) *channel >= 32)
			*p++ = *channel;
		else {
			*p++ = '^';
			*p++ = *channel + 'A'-1;
		}
		channel++;
	}
	*p = '\0';

	return str;
}

