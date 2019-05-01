/*
 test-irc.c : irssi

    Copyright (C) 2017 Will Storey

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

#include <glib.h>
#include <irssi/src/irc/core/irc.h>
#include <string.h>

typedef struct {
	char const *const description;
	char const *const input;
	char const *const input_after;
	char const *const output;
} event_get_param_test_case;

event_get_param_test_case const event_get_param_fixtures[] = {
	{
		.description = "Zero parameters",
		.input       = "",
		.input_after = "",
		.output      = "",
	},
	{
		.description = "One parameter",
		.input       = "#test",
		.input_after = "",
		.output      = "#test",
	},
	{
		.description = "One parameter, trailing space",
		.input       = "#test ",
		.input_after = "",
		.output      = "#test",
	},
	{
		.description = "One parameter, more trailing space",
		.input       = "#test  ",
		.input_after = " ",
		.output      = "#test",
	},
	{
		.description = "Two parameters",
		.input       = "#test +o",
		.input_after = "+o",
		.output      = "#test",
	},
	{
		.description = "Two parameters continued",
		.input       = "+o",
		.input_after = "",
		.output      = "+o",
	},
	{
		.description = "Two parameters with trailing space",
		.input       = "#test +o ",
		.input_after = "+o ",
		.output      = "#test",
	},
	{
		.description = "Two parameters with trailing space continued",
		.input       = "+o ",
		.input_after = "",
		.output      = "+o",
	},
	{
		.description = "Two parameters with inline and trailing space",
		.input       = "#test  +o ",
		.input_after = " +o ",
		.output      = "#test",
	},
	/* TODO: It seems not ideal that the caller has to deal with inline space.
	 */
	{
		.description = "Two parameters with inline and trailing space continued",
		.input       = " +o ",
		.input_after = "+o ",
		.output      = "",
	},
};

static void test_event_get_param(const event_get_param_test_case *test);

typedef struct {
	char const *const description;
	char const *const input;
	char const *const output0;
	char const *const output1;
} event_get_params_test_case;

event_get_params_test_case const event_get_params_fixtures[] = {
	{
		.description = "Only a channel",
		.input       = "#test",
		.output0     = "#test",
		.output1     = "",
	},
	{
		.description = "Only a channel with trailing space",
		.input       = "#test ",
		.output0     = "#test",
		.output1     = "",
	},
	{
		.description = "No :<trailing>, channel mode with one parameter after channel name",
		.input       = "#test +i",
		.output0     = "#test",
		.output1     = "+i",
	},
	{
		.description = "No :<trailing>, channel mode with two parameters after channel name",
		.input       = "#test +o tester",
		.output0     = "#test",
		.output1     = "+o tester",
	},
	{
		.description = "No :<trailing>, channel mode with three parameters afer channel name",
		.input       = "#test +ov tester tester2",
		.output0     = "#test",
		.output1     = "+ov tester tester2",
	},
	{
		.description = "No :<trailing>, channel mode with three parameters afer channel name, bunch of extra space",
		.input       = "#test  +ov  tester  tester2 ",
		.output0     = "#test",
		.output1     = " +ov  tester  tester2 ",
	},
	{
		.description = "Channel mode with one parameter after channel name, :<trailing> at the start of modes",
		.input       = "#test :+i",
		.output0     = "#test",
		.output1     = "+i",
	},
	{
		.description = "Channel mode with two parameters after channel name, :<trailing> at the  start of modes",
		.input       = "#test :+o tester",
		.output0     = "#test",
		.output1     = "+o tester",
	},
	{
		.description = "Channel mode with three parameters after channel name, :<trailing> at the start of modes",
		.input       = "#test :+ov tester tester2",
		.output0     = "#test",
		.output1     = "+ov tester tester2",
	},
	{
		.description = "Channel mode with two parameters after channel name, :<trailing> on the final parameter",
		.input       = "#test +o :tester",
		.output0     = "#test",
		.output1     = "+o tester",
	},
	{
		.description = "Channel mode with three parameters after channel name, :<trailing> on the final parameter",
		.input       = "#test +ov tester :tester2",
		.output0     = "#test",
		.output1     = "+ov tester tester2",
	},
	{
		.description = "Channel mode with three parameters after channel name, :<trailing> on the final parameter, also a second : present",
		.input       = "#test +ov tester :tester2 hi:there",
		.output0     = "#test",
		.output1     = "+ov tester tester2 hi:there",
	},
};

static void test_event_get_params(const event_get_params_test_case *test);

int main(int argc, char **argv)
{
	int i;

	g_test_init(&argc, &argv, NULL);

	for (i = 0; i < G_N_ELEMENTS(event_get_params_fixtures); i++) {
		char *name = g_strdup_printf("/test/event_get_params/%d", i);
		g_test_add_data_func(name, &event_get_params_fixtures[i], (GTestDataFunc)test_event_get_params);
		g_free(name);
	}
	for (i = 0; i < G_N_ELEMENTS(event_get_param_fixtures); i++) {
		char *name = g_strdup_printf("/test/event_get_param/%d", i);
		g_test_add_data_func(name, &event_get_param_fixtures[i], (GTestDataFunc)test_event_get_param);
		g_free(name);
	}

#if GLIB_CHECK_VERSION(2,38,0)
	g_test_set_nonfatal_assertions();
#endif
	return g_test_run();
}

static void test_event_get_param(const event_get_param_test_case *test)
{
	char *buf, *input, *output;

	input = buf = g_strdup(test->input);
	output = event_get_param(&input);

	g_assert_cmpstr(input, ==, test->input_after);
	g_assert_cmpstr(output, ==, test->output);

	g_free(buf);
}

static void test_event_get_params(const event_get_params_test_case *test)
{
	char *output0, *output1, *params;
	output0 = NULL;
	output1 = NULL;
	params = event_get_params(test->input, 2 | PARAM_FLAG_GETREST,
			&output0, &output1);

	/* params happens to always point at the first output */
	g_assert_cmpstr(params, ==, test->output0);
	g_assert_cmpstr(output0, ==, test->output0);
	g_assert_cmpstr(output1, ==, test->output1);

	g_free(params);
}
