/*
 write.c : irssi configuration - write configuration file

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

/* maximum length of lines in config file before splitting them to multiple lines */
#define MAX_CHARS_IN_LINE 70

#define CONFIG_INDENT_SIZE 2
static const char *indent_block = "  "; /* needs to be the same size as CONFIG_INDENT_SIZE! */

/* write needed amount of indentation to the start of the line */
static int config_write_indent(CONFIG_REC *rec)
{
	int n;

	for (n = 0; n < rec->tmp_indent_level/CONFIG_INDENT_SIZE; n++) {
		if (g_io_channel_write_chars(rec->handle, indent_block, CONFIG_INDENT_SIZE,
					     NULL, NULL) == G_IO_STATUS_ERROR)
			return -1;
	}

	return 0;
}

static int config_write_str(CONFIG_REC *rec, const char *str)
{
	const char *strpos, *p;

	g_return_val_if_fail(rec != NULL, -1);
	g_return_val_if_fail(str != NULL, -1);

	strpos = str;
	while (*strpos != '\0') {
		/* fill the indentation */
		if (rec->tmp_last_lf && rec->tmp_indent_level > 0 &&
		    *str != '\n') {
			if (config_write_indent(rec) == -1)
				return -1;
		}

		p = strchr(strpos, '\n');
		if (p == NULL) {
			if (g_io_channel_write_chars(rec->handle, strpos, strlen(strpos),
						     NULL, NULL) == G_IO_STATUS_ERROR)
				return -1;
			strpos = "";
			rec->tmp_last_lf = FALSE;
		} else {
			if (g_io_channel_write_chars(rec->handle, strpos, (int) (p-strpos)+1,
						     NULL, NULL) == G_IO_STATUS_ERROR)
				return -1;
			strpos = p+1;
			rec->tmp_last_lf = TRUE;
		}
	}

	return 0;
}

static int config_has_specials(const char *text)
{
	g_return_val_if_fail(text != NULL, FALSE);

	while (*text != '\0') {
		if (!i_isalnum(*text) && *text != '_')
			return TRUE;
		text++;
	}

	return FALSE;
}

static char *config_escape_string(const char *text)
{
	GString *str;
	char *ret;

	g_return_val_if_fail(text != NULL, NULL);

	str = g_string_new("\"");
	while (*text != '\0') {
		if (*text == '\\' || *text == '"')
			g_string_append_printf(str, "\\%c", *text);
		else if ((unsigned char) *text < 32)
			g_string_append_printf(str, "\\%03o", *text);
		else
			g_string_append_c(str, *text);
		text++;
	}

	g_string_append_c(str, '"');

	ret = str->str;
	g_string_free(str, FALSE);
	return ret;
}

static int config_write_word(CONFIG_REC *rec, const char *word, int string)
{
	char *str;
	int ret;

	g_return_val_if_fail(rec != NULL, -1);
	g_return_val_if_fail(word != NULL, -1);

	if (!string && !config_has_specials(word))
		return config_write_str(rec, word);

	str = config_escape_string(word);
	ret = config_write_str(rec, str);
	g_free(str);

	return ret;
}

static int config_write_block(CONFIG_REC *rec, CONFIG_NODE *node, int list, int line_feeds);

static int config_write_node(CONFIG_REC *rec, CONFIG_NODE *node, int line_feeds)
{
	g_return_val_if_fail(rec != NULL, -1);
	g_return_val_if_fail(node != NULL, -1);

	switch (node->type) {
	case NODE_TYPE_KEY:
		if (config_write_word(rec, node->key, FALSE) == -1 ||
		    config_write_str(rec, " = ") == -1 ||
		    config_write_word(rec, node->value, TRUE) == -1)
			return -1;
		break;
	case NODE_TYPE_VALUE:
		if (config_write_word(rec, node->value, TRUE) == -1)
			return -1;
		break;
	case NODE_TYPE_BLOCK:
		/* key = { */
		if (node->key != NULL) {
			if (config_write_word(rec, node->key, FALSE) == -1 ||
			    config_write_str(rec, " = ") == -1)
				return -1;
		}
		if (config_write_str(rec, line_feeds ? "{\n" : "{ ") == -1)
			return -1;

		/* ..block.. */
		rec->tmp_indent_level += CONFIG_INDENT_SIZE;
		if (config_write_block(rec, node, FALSE, line_feeds) == -1)
			return -1;
		rec->tmp_indent_level -= CONFIG_INDENT_SIZE;

		/* }; */
		if (config_write_str(rec, "}") == -1)
			return -1;
		break;
	case NODE_TYPE_LIST:
		/* key = ( */
		if (node->key != NULL) {
			if (config_write_word(rec, node->key, FALSE) == -1 ||
			    config_write_str(rec, " = ") == -1)
				return -1;
		}
		if (config_write_str(rec, line_feeds ? "(\n" : "( ") == -1)
			return -1;

		/* ..list.. */
		rec->tmp_indent_level += CONFIG_INDENT_SIZE;
		if (config_write_block(rec, node, TRUE, line_feeds) == -1)
			return -1;
		rec->tmp_indent_level -= CONFIG_INDENT_SIZE;

		/* ); */
		if (config_write_str(rec, ")") == -1)
			return -1;
		break;
	case NODE_TYPE_COMMENT:
		if (node->value == NULL)
			break;

		if (config_write_str(rec, "#") == -1 ||
		    config_write_str(rec, node->value) == -1)
			return -1;
		break;
	}

	return 0;
}

static int config_block_get_length(CONFIG_REC *rec, CONFIG_NODE *node);

static int config_node_get_length(CONFIG_REC *rec, CONFIG_NODE *node)
{
	int len;

	switch (node->type) {
	case NODE_TYPE_KEY:
		/* "key = value; " */
		len = 5 + strlen(node->key) + strlen(node->value);
		break;
	case NODE_TYPE_VALUE:
		/* "value, " */
		len = 2 + strlen(node->value);
		break;
	case NODE_TYPE_BLOCK:
	case NODE_TYPE_LIST:
		/* "{ list }; " */
		len = 6;
		if (node->key != NULL) len += strlen(node->key);
		len += config_block_get_length(rec, node);
		break;
	default:
                /* comments always split the line */
		len = 1000;
		break;
	}

	return len;
}

/* return the number of characters `node' and it's subnodes take
   if written to file */
static int config_block_get_length(CONFIG_REC *rec, CONFIG_NODE *node)
{
	GSList *tmp;
	int len;

	len = 0;
	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		CONFIG_NODE *subnode = tmp->data;

                len += config_node_get_length(rec, subnode);
		if (len > MAX_CHARS_IN_LINE) return len;
	}

	return len;
}

/* check if `node' and it's subnodes fit in one line in the config file */
static int config_block_fit_one_line(CONFIG_REC *rec, CONFIG_NODE *node)
{
	g_return_val_if_fail(rec != NULL, 0);
	g_return_val_if_fail(node != NULL, 0);

	return rec->tmp_indent_level +
		config_node_get_length(rec, node) <= MAX_CHARS_IN_LINE;
}

static int config_write_block(CONFIG_REC *rec, CONFIG_NODE *node, int list, int line_feeds)
{
	GSList *tmp;
	int list_line_feeds, node_line_feeds;

	g_return_val_if_fail(rec != NULL, -1);
	g_return_val_if_fail(node != NULL, -1);
	g_return_val_if_fail(is_node_list(node), -1);

	list_line_feeds = !config_block_fit_one_line(rec, node);

	if (!line_feeds && list_line_feeds)
		config_write_str(rec, "\n");

	for (tmp = node->value; tmp != NULL; tmp = tmp->next) {
		CONFIG_NODE *subnode = tmp->data;

		node_line_feeds = !line_feeds ? FALSE : !config_block_fit_one_line(rec, subnode);
		if (config_write_node(rec, subnode, node_line_feeds) == -1)
			return -1;

		if (subnode->type == NODE_TYPE_COMMENT)
			config_write_str(rec, "\n");
		else if (list) {
			if (tmp->next != NULL)
				config_write_str(rec, list_line_feeds ? ",\n" : ", ");
			else
				config_write_str(rec, list_line_feeds ? "\n" : " ");
		} else {
			config_write_str(rec, list_line_feeds ? ";\n" : "; ");
		}
	}

	return 0;
}

int config_write(CONFIG_REC *rec, const char *fname, int create_mode)
{
	int ret;
	int fd;

	g_return_val_if_fail(rec != NULL, -1);
        g_return_val_if_fail(fname != NULL || rec->fname != NULL, -1);
        g_return_val_if_fail(create_mode != -1 || rec->create_mode != -1, -1);

	fd = open(fname != NULL ? fname : rec->fname,
			   O_WRONLY | O_TRUNC | O_CREAT,
			   create_mode != -1 ? create_mode : rec->create_mode);
	if (fd == -1)
		return config_error(rec, g_strerror(errno));

	rec->handle = g_io_channel_unix_new(fd);
	g_io_channel_set_encoding(rec->handle, NULL, NULL);
	g_io_channel_set_close_on_unref(rec->handle, TRUE);
	rec->tmp_indent_level = 0;
	rec->tmp_last_lf = TRUE;
        ret = config_write_block(rec, rec->mainnode, FALSE, TRUE);
	if (ret == -1) {
		/* write error */
		config_error(rec, errno == 0 ? "bug" : g_strerror(errno));
	}

	g_io_channel_unref(rec->handle);
	rec->handle = NULL;

	return ret;
}
