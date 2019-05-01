/*
 test-irc.c : irssi

    Copyright (C) 2018 Will Storey

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

#include <irssi/src/irc/core/channel-events.h>
#include <irssi/src/common.h>
#include <irssi/src/core/core.h>
#include <irssi/src/irc/core/irc.h>
#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/irc/core/irc-servers.h>
#include <irssi/src/core/modules.h>
#include <irssi/src/core/recode.h>
#include <irssi/src/core/settings.h>
#include <irssi/src/core/signals.h>
#include <time.h>
#include <irssi/src/core/args.h>

#define MODULE_NAME "test-channel-events"

typedef struct {
	char const *const description;
	char const *const input;
	char const *const topic;
	char const *const topic_by;
	time_t const topic_time;
} topic_test_case;

static void test_event_topic_get(topic_test_case const *const);
static void test_event_topic(topic_test_case const *const);
static void test_event_topic_info(topic_test_case const *const);
static void setup(void);
static void teardown(void);

static IRC_SERVER_REC *server;
static CHANNEL_REC *channel;

topic_test_case const event_topic_get_test_cases[] = {
	{
		.description = "Normal 332 message with a topic with multiple words",
		.input       = "testnick #test :new topic",
		.topic       = "new topic",
		.topic_by    = NULL,
		.topic_time  = 0,
	},
};

topic_test_case const event_topic_info_test_cases[] = {
	{
		.description = "Normal 333 message",
		.input       = "testnick #test newnick!user@example.com 1533866229",
		.topic       = "initial topic",
		.topic_by    = "newnick!user@example.com",
		.topic_time  = 1533866229,
	},
};

topic_test_case const event_topic_test_cases[] = {
	{
		.description = "Normal TOPIC message",
		.input       = "#test :new topic",
		.topic       = "new topic",
		.topic_by    = "newnick!user@example.com",
		.topic_time  = 0, /* Dynamic */
	},
};

int main(int argc, char **argv)
{
	int i, res;

	g_test_init(&argc, &argv, NULL);

	core_preinit(*argv);
	irssi_gui = IRSSI_GUI_NONE;

	modules_init();
	signals_init();
	settings_init();
	recode_init();
	channel_events_init();

	settings_add_str("lookandfeel", "term_charset", "UTF-8");
	recode_update_charset();

	for (i = 0; i < G_N_ELEMENTS(event_topic_get_test_cases); i++) {
		char *const name = g_strdup_printf("/test/event_topic_get/%d", i);
		g_test_add_data_func(name, &event_topic_get_test_cases[i],
				(GTestDataFunc)test_event_topic_get);
		g_free(name);
	}

	for (i = 0; i < G_N_ELEMENTS(event_topic_test_cases); i++) {
		char *const name = g_strdup_printf("/test/event_topic/%d", i);
		g_test_add_data_func(name, &event_topic_test_cases[i],
				(GTestDataFunc)test_event_topic);
		g_free(name);
	}

	for (i = 0; i < G_N_ELEMENTS(event_topic_info_test_cases); i++) {
		char *const name = g_strdup_printf("/test/event_topic_info/%d", i);
		g_test_add_data_func(name, &event_topic_info_test_cases[i],
				(GTestDataFunc)test_event_topic_info);
		g_free(name);
	}

#if GLIB_CHECK_VERSION(2,38,0)
	g_test_set_nonfatal_assertions();
#endif
	res = g_test_run();

	channel_events_deinit();
	recode_deinit();
	settings_deinit();
	signals_deinit();
	modules_deinit();

	return res;
}

static void test_event_topic_get(topic_test_case const *const test)
{
	setup();

	signal_emit("event 332", 2, server, test->input);

	g_assert_cmpstr(channel->topic,      ==, test->topic);
	g_assert_cmpstr(channel->topic_by,   ==, test->topic_by);
	g_assert_cmpint(channel->topic_time, ==, test->topic_time);

	teardown();
}

static void test_event_topic(topic_test_case const *const test)
{
	time_t now;

	setup();

	now = time(NULL);
	signal_emit("event topic", 4, server, test->input, "newnick",
			"user@example.com");

	g_assert_cmpstr(channel->topic,      ==, test->topic);
	g_assert_cmpstr(channel->topic_by,   ==, test->topic_by);
	g_assert_cmpint(channel->topic_time, >=, now);

	teardown();
}

static void test_event_topic_info(topic_test_case const *const test)
{
	setup();

	signal_emit("event 333", 2, server, test->input);

	g_assert_cmpstr(channel->topic,      ==, test->topic);
	g_assert_cmpstr(channel->topic_by,   ==, test->topic_by);
	g_assert_cmpint(channel->topic_time, ==, test->topic_time);

	teardown();
}

static void setup(void)
{
	server = g_new0(IRC_SERVER_REC, 1);
	MODULE_DATA_INIT(server);
	server->type = module_get_uniq_id("SERVER", 0);

	channel = g_new0(CHANNEL_REC, 1);
	channel->name = "#test";
	server->channels = g_slist_append(server->channels, channel);

	g_assert_nonnull(channel_find(SERVER(server), "#test"));

	channel->topic = g_strdup("initial topic");
	channel->topic_by = g_strdup("initialnick!user@example.com");
	channel->topic_time = 123;
}

static void teardown(void)
{
	g_slist_free(server->channels);
	MODULE_DATA_DEINIT(server);
	g_free(server);

	g_free(channel->topic);
	g_free(channel->topic_by);
	g_free(channel);
}
