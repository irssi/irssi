#include <irssi/src/common.h>
#include <irssi/src/fe-common/core/formats.h>

#define MAX_LENGTH 5

typedef struct {
	char const *const description;
	char const *const input;
	int const result[ MAX_LENGTH ];
} format_real_length_test_case;

static void test_format_real_length(const format_real_length_test_case *test);

format_real_length_test_case const format_real_length_fixtures[] = {
	{
		.description = "",
		.input = "%4%w ",
		.result = { 4, 5, 5, -1 },
	},
};

int main(int argc, char **argv)
{
	int i;

	g_test_init(&argc, &argv, NULL);

	for (i = 0; i < G_N_ELEMENTS(format_real_length_fixtures); i++) {
		char *name = g_strdup_printf("/test/format_real_length/%d", i);
		g_test_add_data_func(name, &format_real_length_fixtures[i], (GTestDataFunc)test_format_real_length);
		g_free(name);
	}

#if GLIB_CHECK_VERSION(2,38,0)
	g_test_set_nonfatal_assertions();
#endif
	return g_test_run();
}

static void test_format_real_length(const format_real_length_test_case *test)
{
	int j, len;

	g_test_message("Testing format %s", test->input);

	for (j = 0; test->result[j] != -1; j++) {
		len = format_real_length(test->input, j);
		g_assert_cmpint(len, ==, test->result[j]);
	}

	return;
}
