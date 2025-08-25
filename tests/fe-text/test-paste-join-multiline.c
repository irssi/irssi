#include <irssi/src/common.h>
#include <irssi/src/fe-text/gui-readline.c>

typedef struct {
	char const *const description;
	char const *const input;
	char const *const result;
} paste_join_multiline_test_case;

static void test_paste_join_multiline(const paste_join_multiline_test_case *test);

paste_join_multiline_test_case const paste_join_multiline_fixture[] = {
	{
		.description = "Lines should be joined, separator NL",
		.input = "<User> A1\n       B22\n       C33",
		.result = "<User> A1 B22 C33",
	},
	{
		.description = "Lines should be joined, separator LF",
		.input = "<User> A1\r       B22\r       C33",
		.result = "<User> A1 B22 C33",
	},
	{
		.description = "Lines should be joined, white space should be skipped",
		.input = "<User> A1 \n       B22 \n       C33 ",
		.result = "<User> A1 B22 C33 ",
	},
};

int main(int argc, char **argv)
{
	int i;

	g_test_init(&argc, &argv, NULL);

	for (i = 0; i < G_N_ELEMENTS(paste_join_multiline_fixture); i++) {
		char *name = g_strdup_printf("/test/paste_join_multiline/%d", i);
		g_test_add_data_func(name, &paste_join_multiline_fixture[i], (GTestDataFunc)test_paste_join_multiline);
		g_free(name);
	}

#if GLIB_CHECK_VERSION(2,38,0)
	g_test_set_nonfatal_assertions();
#endif
	return g_test_run();
}

static void test_paste_join_multiline(const paste_join_multiline_test_case *test)
{
	char *resultstr, *t1;
	GArray *buffer = g_array_new(FALSE, FALSE, sizeof(unichar));

	g_test_message("Testing: %s", test->description);
	g_test_message("INPUT: \"%s\"", (t1 = g_strescape(test->input, NULL)));
	g_free(t1);

	{
		glong buf_len;
		buffer->data = (char *) g_utf8_to_ucs4_fast(test->input, -1, &buf_len);
		buffer->len = buf_len;
	}

	paste_buffer_join_lines(buffer);
	resultstr = g_ucs4_to_utf8((unichar *) buffer->data, buffer->len, NULL, NULL, NULL);

	g_assert_cmpstr(resultstr, ==, test->result);

	g_free(resultstr);
	g_array_free(buffer, TRUE);

	return;
}
