#ifndef __IRSSI_CONFIG_H
#define __IRSSI_CONFIG_H

#include <proplist.h>

extern proplist_t cprop;

/* make proplist handling easier */
gchar *config_get_str(proplist_t prop, gchar *key, gchar *def);
gint config_get_int(proplist_t prop, gchar *key, gint def);
gboolean config_get_bool(proplist_t prop, gchar *key, gboolean def);
proplist_t config_get_prop(proplist_t prop, gchar *key);

proplist_t config_set_str(proplist_t prop, gchar *key, gchar *value);
proplist_t config_set_int(proplist_t prop, gchar *key, gint value);
proplist_t config_set_bool(proplist_t prop, gchar *key, gboolean value);

proplist_t config_section(proplist_t *prop, gchar *section);
proplist_t config_list_section(proplist_t *prop, gchar *section);
proplist_t config_make_dict(proplist_t prop, gchar *section);
proplist_t config_clean_key(proplist_t prop, gchar *key);

gint config_list_find(proplist_t prop, gchar *key, gchar *value);

#endif
