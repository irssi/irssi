/*
 perl-fe.c : irssi

    Copyright (C) 2001 Timo Sirainen

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

#include "module.h"
#include "signals.h"

#include "fe-common/core/themes.h"
#include "fe-common/core/formats.h"

#include "perl-common.h"

static void perl_unregister_theme(const char *package)
{
	FORMAT_REC *formats;
	int n;

	formats = g_hash_table_lookup(default_formats, package);
	if (formats == NULL) return;

	for (n = 0; formats[n].def != NULL; n++) {
		g_free(formats[n].tag);
		g_free(formats[n].def);
	}
	g_free(formats);
	theme_unregister_module(package);
}

static void sig_script_destroy(const char *type, const char *name,
			       const char *package)
{
	if (strcmp(type, "PERL") == 0)
		perl_unregister_theme(package);
}

static void sig_perl_stop(void)
{
	GSList *tmp;
        char *package;

	/* themes */
	for (tmp = perl_scripts; tmp != NULL; tmp = tmp->next) {
		package = g_strdup_printf("Irssi::Script::%s",
					  (char *) tmp->data);
		perl_unregister_theme(package);
		g_free(package);
	}
}

void fe_perl_init(void)
{
	signal_add("script destroy", (SIGNAL_FUNC) sig_script_destroy);
	signal_add("perl stop", (SIGNAL_FUNC) sig_perl_stop);
}

void fe_perl_deinit(void)
{
	signal_remove("script destroy", (SIGNAL_FUNC) sig_script_destroy);
	signal_remove("perl stop", (SIGNAL_FUNC) sig_perl_stop);
}
