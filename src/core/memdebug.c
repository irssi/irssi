/*
 memdebug.c : irssi

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <gmodule.h>

/*#define ENABLE_BUFFER_CHECKS*/
#define BUFFER_CHECK_SIZE 5
#define MIN_BUFFER_CHECK_SIZE 2

typedef struct {
	void *p;
	int size;
	char *file;
	int line;
	char *comment;
} MEM_REC;

static GHashTable *data = NULL, *preallocs = NULL;
static const char *comment = "";

static void add_flow_checks(char *p, unsigned long size)
{
#ifdef ENABLE_BUFFER_CHECKS
	int n;

	for (n = 0; n < BUFFER_CHECK_SIZE; n++)
		p[n] = n ^ 0x7f;
	for (n = 0; n < BUFFER_CHECK_SIZE; n++)
		p[size-BUFFER_CHECK_SIZE+n] = n ^ 0x7f;
#endif
}

void ig_memcheck_rec(void *key, MEM_REC *rec)
{
	guchar *p;
	int n;

	if (rec->size != INT_MIN){
		p = rec->p;

		for (n = 0; n < MIN_BUFFER_CHECK_SIZE; n++)
			if (p[n] != (n ^ 0x7f))
				g_error("buffer underflow, file %s line %d!\n", rec->file, rec->line);

		for (n = 0; n < MIN_BUFFER_CHECK_SIZE; n++)
			if (p[rec->size-BUFFER_CHECK_SIZE+n] != (n ^ 0x7f))
				g_error("buffer overflow, file %s line %d!\n", rec->file, rec->line);
	}
}

static void mem_check(void)
{
#ifdef ENABLE_BUFFER_CHECKS
	g_hash_table_foreach(data, (GHFunc) ig_memcheck_rec, NULL);
#endif
}

static void data_add(char *p, int size, const char *file, int line)
{
	MEM_REC *rec;

	if (size <= 0 && size != INT_MIN)
		g_error("size = %d, file %s line %d", size, file, line);

	if (data == NULL) {
		data = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);
		preallocs = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);
	}

	if (g_hash_table_lookup(data, p) != NULL)
		g_error("data_add() already malloc()'ed %p (in %s:%d)", p, file, line);

	rec = g_new(MEM_REC, 1);
	g_hash_table_insert(data, p, rec);

	rec->p = p;
	rec->size = size;
	rec->file = g_strdup(file);
	rec->line = line;
	rec->comment = g_strdup(comment);

	if (size == INT_MIN)
		g_hash_table_insert(preallocs, p-BUFFER_CHECK_SIZE, p);
	else
		add_flow_checks(p, size);
	mem_check();
}

static void data_clear(char *p)
{
	MEM_REC *rec;

	if (g_hash_table_lookup(preallocs, p) != NULL)
		p += BUFFER_CHECK_SIZE;

	rec = g_hash_table_lookup(data, p);
	if (rec != NULL && rec->size > 0)
		memset(p, 'F', rec->size);
}

static void *data_remove(char *p, const char *file, int line)
{
	MEM_REC *rec;

	mem_check();

	if (g_hash_table_lookup(preallocs, p) != NULL) {
		g_hash_table_remove(preallocs, p);
		p += BUFFER_CHECK_SIZE;
	}

	rec = g_hash_table_lookup(data, p);
	if (rec == NULL) {
		g_warning("data_remove() data %p not found (in %s:%d)", p, file, line);
		return p+BUFFER_CHECK_SIZE;
	}

	g_hash_table_remove(data, p);
	g_free(rec->file);
	g_free(rec->comment);
	g_free(rec);

	return p;
}

void *ig_malloc(int size, const char *file, int line)
{
	char *p;

	size += BUFFER_CHECK_SIZE*2;
	p = g_malloc(size);
	data_add(p, size, file, line);
	return (void *) (p+BUFFER_CHECK_SIZE);
}

void *ig_malloc0(int size, const char *file, int line)
{
	char *p;

	size += BUFFER_CHECK_SIZE*2;
	p = g_malloc0(size);
	data_add(p, size, file, line);
	return (void *) (p+BUFFER_CHECK_SIZE);
}

void *ig_realloc(void *mem, unsigned long size, const char *file, int line)
{
	char *p, *oldmem = mem;

	size += BUFFER_CHECK_SIZE*2;
	oldmem -= BUFFER_CHECK_SIZE;
	data_remove(oldmem, file, line);
	p = g_realloc(oldmem, size);
	data_add(p, size, file, line);
	return (void *) (p+BUFFER_CHECK_SIZE);
}

char *ig_strdup(const char *str, const char *file, int line)
{
	void *p;

	if (str == NULL) return NULL;

	p = ig_malloc(strlen(str)+1, file, line);
	strcpy(p, str);

	return p;
}

char *ig_strndup(const char *str, int count, const char *file, int line)
{
	char *p;

	if (str == NULL) return NULL;

	p = ig_malloc(count+1, file, line);
	strncpy(p, str, count); p[count] = '\0';

	return p;
}

char *ig_strconcat(const char *file, int line, const char *str, ...)
{
  guint	  l;
  va_list args;
  char	  *s;
  char	  *concat;

  g_return_val_if_fail (str != NULL, NULL);

  l = 1 + strlen (str);
  va_start (args, str);
  s = va_arg (args, char*);
  while (s)
    {
      l += strlen (s);
      s = va_arg (args, char*);
    }
  va_end (args);

  concat = ig_malloc(l, file, line);
  concat[0] = 0;

  strcat (concat, str);
  va_start (args, str);
  s = va_arg (args, char*);
  while (s)
    {
      strcat (concat, s);
      s = va_arg (args, char*);
    }
  va_end (args);

  return concat;
}

char *ig_strdup_printf(const char *file, int line, const char *format, ...)
{
	char *buffer, *p;
	va_list args;

	va_start (args, format);
	buffer = g_strdup_vprintf (format, args);
	va_end (args);

	p = ig_malloc(strlen(buffer)+1, file, line);
	strcpy(p, buffer);
	g_free(buffer);

	return p;
}

char *ig_strdup_vprintf(const char *file, int line, const char *format, va_list args)
{
	char *buffer, *p;

	buffer = g_strdup_vprintf (format, args);

	p = ig_malloc(strlen(buffer)+1, file, line);
	strcpy(p, buffer);
	g_free(buffer);

	return p;
}

void ig_free(void *p)
{
	char *cp = p;

	if (cp == NULL) g_error("ig_free() : trying to free NULL");

	cp -= BUFFER_CHECK_SIZE;
	data_clear(cp);
	cp = data_remove(cp, "??", 0);
	if (cp != NULL) g_free(cp);
}

GString *ig_string_new(const char *file, int line, const char *str)
{
	GString *ret;

	ret = g_string_new(str);
	data_add((void *) ret, INT_MIN, file, line);
	return ret;
}

void ig_string_free(const char *file, int line, GString *str, gboolean freeit)
{
	data_remove((void *) str, file, line);
	if (!freeit)
		data_add(str->str, INT_MIN, file, line);

	g_string_free(str, freeit);
}

char *ig_strjoinv(const char *file, int line, const char *sepa, char **array)
{
	char *ret;

	ret = g_strjoinv(sepa, array);
	data_add(ret, INT_MIN, file, line);
	return ret;
}

char *ig_dirname(const char *file, int line, const char *fname)
{
	char *ret;

	ret = g_dirname(fname);
	data_add(ret, INT_MIN, file, line);
	return ret;
}

char *ig_module_build_path(const char *file, int line, const char *dir, const char *module)
{
	char *ret;

	ret = g_module_build_path(dir, module);
	data_add(ret, INT_MIN, file, line);
	return ret;
}

void ig_profile_line(void *key, MEM_REC *rec)
{
	char *data;

	if (*rec->comment == '\0' &&
	    (strcmp(rec->file, "ig_strdup_printf") == 0 ||
	     strcmp(rec->file, "ig_strdup_vprintf") == 0 ||
	     strcmp(rec->file, "ig_strconcat") == 0 ||
	     strcmp(rec->file, "ig_string_free (free = FALSE)") == 0))
		data = (char *) rec->p + BUFFER_CHECK_SIZE;
	else
		data = rec->comment;
	fprintf(stderr, "%s:%d %d bytes (%s)\n", rec->file, rec->line, rec->size, data);
}

void ig_mem_profile(void)
{
    g_hash_table_foreach(data, (GHFunc) ig_profile_line, NULL);
    g_hash_table_destroy(data);
    g_hash_table_destroy(preallocs);
}

static MEM_REC *largest[10];

void ig_profile_largest(void *key, MEM_REC *rec)
{
    int n;

    for (n = 0; n < 10; n++)
    {
	if (largest[n] == NULL || rec->size > largest[n]->size)
	{
	    g_memmove(largest+n+1, largest+n, sizeof(void *)*(9-n));
	    largest[n] = rec;
	}
    }
}

void ig_mem_profile_largest(void)
{
    /*int n;*/

    memset(&largest, 0, sizeof(MEM_REC*)*10);
    /*g_hash_table_foreach(data, (GHFunc) ig_profile_largest, NULL);

    for (n = 0; n < 10 && largest[n] != NULL; n++)
    {
	ig_profile_line(NULL, largest[n]);
    }*/
}

void ig_set_data(const char *data)
{
    comment = data;
}
