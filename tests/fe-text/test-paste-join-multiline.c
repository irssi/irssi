#include "common.h"
#include "gui-readline.c"

typedef struct {
	char const *const description;
	char const *const input;
	char const *const result;
} paste_join_multiline_test_case;

static void test_paste_join_multiline(const paste_join_multiline_test_case *test);

paste_join_multiline_test_case const paste_join_multiline_fixture[] = {
	{
		.description = "Lines should be joined, separator NL",
		.input = "<User> hello world\n       how are you\n       screen is narrow",
		.result = "<User> hello world how are you screen is narrow",
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
	char *resultstr;
	GArray *buffer = g_array_new(FALSE, FALSE, sizeof(unichar));

	g_test_message("Testing: %s", test->description);

	buffer->data = (char *) g_utf8_to_ucs4_fast(test->input, -1, (glong *) &buffer->len);
	paste_buffer_join_lines(buffer);
	resultstr = g_ucs4_to_utf8((unichar *) buffer->data, buffer->len, NULL, NULL, NULL);

	g_assert_cmpstr(resultstr, ==, test->result);

	g_free(resultstr);
	g_array_free(buffer, TRUE);

	return;
}
