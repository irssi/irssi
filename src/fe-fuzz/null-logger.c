#include <irssi/src/fe-fuzz/null-logger.h>

#include <glib.h>

static void null_logger(const gchar *log_domain,
			GLogLevelFlags log_level,
			const gchar *message,
			gpointer user_data)
{
	return;
}

void g_log_set_null_logger(void)
{
	g_log_set_default_handler(null_logger, NULL);
}
