/*
 parse.c : irssi configuration - parse configuration file

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

static int g_istr_equal(gconstpointer v, gconstpointer v2)
{
	return g_strcasecmp((const char *) v, (const char *) v2) == 0;
}

/* a char* hash function from ASU */
static unsigned int g_istr_hash(gconstpointer v)
{
	const char *s = (const char *) v;
	unsigned int h = 0, g;

	while (*s != '\0') {
		h = (h << 4) + i_toupper(*s);
		if ((g = h & 0xf0000000UL)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		s++;
	}

	return h /* % M */;
}

int config_error(CONFIG_REC *rec, const char *msg)
{
	g_free_and_null(rec->last_error);
	rec->last_error = g_strdup(msg);
	return -1;
}

static int node_add_comment(CONFIG_NODE *parent, const char *str)
{
	CONFIG_NODE *node;

	g_return_val_if_fail(parent != NULL, -1);

	if (!is_node_list(parent))
		return -1;

	node = g_new0(CONFIG_NODE, 1);
	node->type = NODE_TYPE_COMMENT;
	node->value = str == NULL ? NULL : g_strdup(str);

	parent->value = g_slist_append(parent->value, node);
	return 0;
}

/* same as g_scanner_get_next_token() except skips and reads the comments */
static void config_parse_get_token(GScanner *scanner, CONFIG_NODE *node)
{
	int prev_empty = FALSE;

	for (;;) {
		g_scanner_get_next_token(scanner);

		if (scanner->token == G_TOKEN_COMMENT_SINGLE)
			node_add_comment(node, scanner->value.v_string);
		else if (scanner->token == '\n') {
			if (prev_empty) node_add_comment(node, NULL);
		} else {
			if (scanner->token == G_TOKEN_INT) {
				scanner->token = G_TOKEN_STRING;
				scanner->value.v_string = g_strdup_printf("%lu", scanner->value.v_int);
			}
			break;
		}

		prev_empty = TRUE;
	}
}

/* same as g_scanner_peek_next_token() except skips and reads the comments */
static void config_parse_peek_token(GScanner *scanner, CONFIG_NODE *node)
{
	int prev_empty = FALSE;

	for (;;) {
		g_scanner_peek_next_token(scanner);

		if (scanner->next_token == G_TOKEN_COMMENT_SINGLE)
			node_add_comment(node, scanner->next_value.v_string);
		else if (scanner->next_token == '\n') {
			if (prev_empty) node_add_comment(node, NULL);
		} else
			break;

		prev_empty = TRUE;
		g_scanner_get_next_token(scanner);
	}
}

/* get optional token, optionally warn if it's missing */
static void config_parse_warn_missing(CONFIG_REC *rec, CONFIG_NODE *node,
				      GTokenType expected_token, int print_warning)
{
	config_parse_peek_token(rec->scanner, node);
	if (rec->scanner->next_token == expected_token) {
		g_scanner_get_next_token(rec->scanner);
		return;
	}

        if (print_warning)
		g_scanner_warn(rec->scanner, "Warning: missing '%c'", expected_token);
}

static void config_parse_loop(CONFIG_REC *rec, CONFIG_NODE *node, GTokenType expect);

static GTokenType config_parse_symbol(CONFIG_REC *rec, CONFIG_NODE *node)
{
	CONFIG_NODE *newnode;
	GTokenType last_char;
	int print_warning;
	char *key;

	g_return_val_if_fail(rec != NULL, G_TOKEN_ERROR);
	g_return_val_if_fail(node != NULL, G_TOKEN_ERROR);

	config_parse_get_token(rec->scanner, node);

	last_char = (GTokenType) (node->type == NODE_TYPE_LIST ? ',' : ';');

	/* key */
	key = NULL;
	if (node->type != NODE_TYPE_LIST &&
	    (rec->scanner->token == G_TOKEN_STRING)) {
		key = g_strdup(rec->scanner->value.v_string);

                config_parse_warn_missing(rec, node, '=', TRUE);
		config_parse_get_token(rec->scanner, node);
	}

 	switch (rec->scanner->token) {
	case G_TOKEN_STRING:
		/* value */
		config_node_set_str(rec, node, key, rec->scanner->value.v_string);
		g_free_not_null(key);

		print_warning = TRUE;
		if (node->type == NODE_TYPE_LIST) {
			/* if it's last item it doesn't need comma */
			config_parse_peek_token(rec->scanner, node);
			if (rec->scanner->next_token == ')')
				print_warning = FALSE;
		}

		config_parse_warn_missing(rec, node, last_char, print_warning);
		break;

	case '{':
		/* block */
		if (key == NULL && node->type != NODE_TYPE_LIST)
			return G_TOKEN_ERROR;

		newnode = config_node_section(node, key, NODE_TYPE_BLOCK);
		config_parse_loop(rec, newnode, (GTokenType) '}');
		g_free_not_null(key);

		config_parse_get_token(rec->scanner, node);
		if (rec->scanner->token != '}')
			return (GTokenType) '}';

		config_parse_warn_missing(rec, node, last_char, FALSE);
		break;

	case '(':
		/* list */
		if (key == NULL)
			return G_TOKEN_ERROR;
		newnode = config_node_section(node, key, NODE_TYPE_LIST);
		config_parse_loop(rec, newnode, (GTokenType) ')');
		g_free_not_null(key);

		config_parse_get_token(rec->scanner, node);
		if (rec->scanner->token != ')')
			return (GTokenType) ')';

		config_parse_warn_missing(rec, node, last_char, FALSE);
		break;

	default:
		/* error */
		g_free_not_null(key);
		return G_TOKEN_STRING;
	}

        return G_TOKEN_NONE;
}

static void config_parse_loop(CONFIG_REC *rec, CONFIG_NODE *node, GTokenType expect)
{
	GTokenType expected_token;

	g_return_if_fail(rec != NULL);
	g_return_if_fail(node != NULL);

	for (;;) {
		config_parse_peek_token(rec->scanner, node);
		if (rec->scanner->next_token == expect ||
		    rec->scanner->next_token == G_TOKEN_EOF) break;

		expected_token = config_parse_symbol(rec, node);
		if (expected_token != G_TOKEN_NONE) {
			if (expected_token == G_TOKEN_ERROR)
				expected_token = G_TOKEN_NONE;
			g_scanner_unexp_token(rec->scanner, expected_token, NULL, "symbol", NULL, NULL, TRUE);
		}
	}
}

static void config_parse_error_func(GScanner *scanner, char *message, int is_error)
{
	CONFIG_REC *rec = scanner->user_data;
	char *old;

	old = rec->last_error;
	rec->last_error = g_strdup_printf("%s%s:%d: %s%s\n",
					  old == NULL ? "" : old,
					  scanner->input_name, scanner->line,
					  is_error ? "error: " : "",
					  message);
        g_free_not_null(old);
}

void config_parse_init(CONFIG_REC *rec, const char *name)
{
	GScanner *scanner;

	g_free_and_null(rec->last_error);
	config_nodes_remove_all(rec);

	rec->scanner = scanner = g_scanner_new(NULL);
	scanner->config->skip_comment_single = FALSE;
	scanner->config->cset_identifier_first = G_CSET_a_2_z"_0123456789"G_CSET_A_2_Z;
	scanner->config->cset_skip_characters = " \t";
	scanner->config->scan_binary = FALSE;
	scanner->config->scan_octal = FALSE;
	scanner->config->scan_float = FALSE;
	scanner->config->scan_string_sq = TRUE;
	scanner->config->scan_string_dq = TRUE;
	scanner->config->scan_identifier_1char = TRUE;
	scanner->config->identifier_2_string = TRUE;

	scanner->user_data = rec;
	scanner->input_name = name;
	scanner->msg_handler = (GScannerMsgFunc) config_parse_error_func;
}

int config_parse(CONFIG_REC *rec)
{
	int fd;

	g_return_val_if_fail(rec != NULL, -1);
	g_return_val_if_fail(rec->fname != NULL, -1);

	fd = open(rec->fname, O_RDONLY);
	if (fd == -1)
		return config_error(rec, g_strerror(errno));

	config_parse_init(rec, rec->fname);
	g_scanner_input_file(rec->scanner, fd);
	config_parse_loop(rec, rec->mainnode, G_TOKEN_EOF);
	g_scanner_destroy(rec->scanner);

	close(fd);

	return rec->last_error == NULL ? 0 : -1;
}

int config_parse_data(CONFIG_REC *rec, const char *data, const char *input_name)
{
	config_parse_init(rec, input_name);
	g_scanner_input_text(rec->scanner, data, strlen(data));
	config_parse_loop(rec, rec->mainnode, G_TOKEN_EOF);
	g_scanner_destroy(rec->scanner);

	return rec->last_error == NULL ? 0 : -1;
}

CONFIG_REC *config_open(const char *fname, int create_mode)
{
	CONFIG_REC *rec;
	int f;

	if (fname != NULL) {
		f = open(fname, O_RDONLY | (create_mode != -1 ? O_CREAT : 0), create_mode);
		if (f == -1) return NULL;
		close(f);
	}

	rec = g_new0(CONFIG_REC, 1);
	rec->fname = fname == NULL ? NULL : g_strdup(fname);
	rec->create_mode = create_mode;
	rec->mainnode = g_new0(CONFIG_NODE, 1);
	rec->mainnode->type = NODE_TYPE_BLOCK;
	rec->cache = g_hash_table_new((GHashFunc) g_istr_hash, (GCompareFunc) g_istr_equal);
	rec->cache_nodes = g_hash_table_new((GHashFunc) g_direct_hash, (GCompareFunc) g_direct_equal);

	return rec;
}

void config_close(CONFIG_REC *rec)
{
	g_return_if_fail(rec != NULL);

	config_nodes_remove_all(rec);
	g_free(rec->mainnode);

	g_hash_table_foreach(rec->cache, (GHFunc) g_free, NULL);
	g_hash_table_destroy(rec->cache);
	g_hash_table_destroy(rec->cache_nodes);
	g_free_not_null(rec->last_error);
	g_free_not_null(rec->fname);
	g_free(rec);
}

void config_change_file_name(CONFIG_REC *rec, const char *fname, int create_mode)
{
	g_return_if_fail(rec != NULL);
	g_return_if_fail(fname != NULL);

	g_free_not_null(rec->fname);
	rec->fname = g_strdup(fname);

	if (create_mode != -1)
		rec->create_mode = create_mode;
}
