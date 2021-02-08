/*
 write-buffer.c : irssi

    Copyright (C) 2001 Timo Sirainen

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
#include <irssi/src/core/signals.h>
#include <irssi/src/core/commands.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/write-buffer.h>

#define BUFFER_BLOCK_SIZE 2048

typedef struct {
	char *active_block;
        int active_block_pos;

	GSList *blocks;
} BUFFER_REC;

static GSList *empty_blocks;
static GHashTable *buffers;
static int block_count;

static int write_buffer_max_blocks;
static int timeout_tag;

static void write_buffer_new_block(BUFFER_REC *rec)
{
	char *block;

	if (empty_blocks == NULL)
		block = g_malloc(BUFFER_BLOCK_SIZE);
	else {
		block = empty_blocks->data;
                empty_blocks = g_slist_remove(empty_blocks, block);
	}

        block_count++;
	rec->active_block = block;
        rec->active_block_pos = 0;
	rec->blocks = g_slist_append(rec->blocks, block);
}

int write_buffer(int handle, const void *data, int size)
{
	BUFFER_REC *rec;
        const char *cdata = data;
	int next_size;

	if (size <= 0)
		return size;

	if (write_buffer_max_blocks <= 0) {
		/* no write buffer */
                return write(handle, data, size);
	}

	rec = g_hash_table_lookup(buffers, GINT_TO_POINTER(handle));
	if (rec == NULL) {
		rec = g_new0(BUFFER_REC, 1);
                write_buffer_new_block(rec);
		g_hash_table_insert(buffers, GINT_TO_POINTER(handle), rec);
	}

	while (size > 0) {
                if (rec->active_block_pos == BUFFER_BLOCK_SIZE)
			write_buffer_new_block(rec);

		next_size = size < BUFFER_BLOCK_SIZE-rec->active_block_pos ?
			size : BUFFER_BLOCK_SIZE-rec->active_block_pos;
		memcpy(rec->active_block+rec->active_block_pos,
		       cdata, next_size);

		rec->active_block_pos += next_size;
		cdata += next_size;
                size -= next_size;
	}

	if (block_count > write_buffer_max_blocks)
                write_buffer_flush();

        return size;
}

static int write_buffer_flush_rec(void *handlep, BUFFER_REC *rec)
{
	GSList *tmp;
        int handle, size;

        handle = GPOINTER_TO_INT(handlep);
	for (tmp = rec->blocks; tmp != NULL; tmp = tmp->next) {
		size = tmp->data != rec->active_block ? BUFFER_BLOCK_SIZE :
			rec->active_block_pos;
		if (write(handle, tmp->data, size) != size) {
			g_warning("Failed to write(): %s", strerror(errno));
		}
	}

        empty_blocks = g_slist_concat(empty_blocks, rec->blocks);
	g_free(rec);
        return TRUE;
}

void write_buffer_flush(void)
{
	g_slist_foreach(empty_blocks, (GFunc) g_free, NULL);
	g_slist_free(empty_blocks);
        empty_blocks = NULL;

	g_hash_table_foreach_remove(buffers,
				    (GHRFunc) write_buffer_flush_rec, NULL);
        block_count = 0;
}

static int flush_timeout(void)
{
	write_buffer_flush();
        return 1;
}

static void read_settings(void)
{
	write_buffer_flush();

	write_buffer_max_blocks =
		settings_get_size("write_buffer_size") / BUFFER_BLOCK_SIZE;

	if (settings_get_time("write_buffer_timeout") > 0) {
		if (timeout_tag == -1) {
			timeout_tag = g_timeout_add(settings_get_time("write_buffer_timeout"),
						    (GSourceFunc) flush_timeout,
						    NULL);
		}
	} else if (timeout_tag != -1) {
		g_source_remove(timeout_tag);
                timeout_tag = -1;
	}
}

static void cmd_flushbuffer(void)
{
        write_buffer_flush();
}

void write_buffer_init(void)
{
	settings_add_time("misc", "write_buffer_timeout", "0");
	settings_add_size("misc", "write_buffer_size", "0");

	buffers = g_hash_table_new((GHashFunc) g_direct_hash,
				   (GCompareFunc) g_direct_equal);

        empty_blocks = NULL;
        block_count = 0;

	timeout_tag = -1;
	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC) read_settings);
        command_bind("flushbuffer", NULL, (SIGNAL_FUNC) cmd_flushbuffer);
}

void write_buffer_deinit(void)
{
	if (timeout_tag != -1)
		g_source_remove(timeout_tag);

        write_buffer_flush();
        g_hash_table_destroy(buffers);

	g_slist_foreach(empty_blocks, (GFunc) g_free, NULL);
        g_slist_free(empty_blocks);

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);
	command_unbind("flushbuffer",  (SIGNAL_FUNC) cmd_flushbuffer);
}
