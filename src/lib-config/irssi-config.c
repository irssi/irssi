/*
 config.c : Functions for reading onfiguration file

    Copyright (C) 1999 Timo Sirainen

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

#include "../common.h"
#include "../irc-base/irc-base.h"

proplist_t cprop = NULL;

gboolean config_get_bool(proplist_t prop, gchar *key, gboolean def)
{
    proplist_t pkey, pvalue;
    gchar *value;

    if (prop == NULL)
	return def;

    pkey = PLMakeString(key);
    pvalue = PLGetDictionaryEntry(prop, pkey);
    PLRelease(pkey);
    if (pvalue == NULL) return def;

    value = PLGetString(pvalue);
    return toupper(*value) == 'T' || toupper(*value) == 'Y';
}

gint config_get_int(proplist_t prop, gchar *key, gint def)
{
    proplist_t pkey, pvalue;
    gint num;

    if (prop == NULL)
	return def;

    pkey = PLMakeString(key);
    pvalue = PLGetDictionaryEntry(prop, pkey);
    PLRelease(pkey);
    if (pvalue == NULL) return def;

    return sscanf(PLGetString(pvalue), "%d", &num) != 1 ? def : num;
}

gchar *config_get_str(proplist_t prop, gchar *key, gchar *def)
{
    proplist_t pkey, pvalue;

    if (prop == NULL)
	return def;

    pkey = PLMakeString(key);
    pvalue = PLGetDictionaryEntry(prop, pkey);
    PLRelease(pkey);

    return pvalue == NULL ? def : PLGetString(pvalue);
}

proplist_t config_get_prop(proplist_t prop, gchar *key)
{
    proplist_t ret, pkey;

    pkey = PLMakeString(key);
    ret = PLGetDictionaryEntry(prop, pkey);
    PLRelease(pkey);

    return ret;
}

proplist_t config_make_dict(proplist_t prop, gchar *section)
{
    proplist_t psect, pkey;

    pkey = PLMakeString(section);
    psect = PLMakeDictionaryFromEntries(NULL, NULL);
    prop = PLInsertDictionaryEntry(prop, pkey, psect);
    return prop;
}

proplist_t config_set_str(proplist_t prop, gchar *key, gchar *value)
{
    proplist_t pkey, pvalue;

    pkey = PLMakeString(key); pvalue = PLMakeString(value);
    prop = PLInsertDictionaryEntry(prop, pkey, pvalue);
    PLRelease(pkey); PLRelease(pvalue);
    return prop;
}

proplist_t config_set_int(proplist_t prop, gchar *key, gint value)
{
    proplist_t pkey, pvalue;
    gchar *strval;

    strval = g_strdup_printf("%d", value);
    pkey = PLMakeString(key); pvalue = PLMakeString(strval);
    prop = PLInsertDictionaryEntry(prop, pkey, pvalue);
    PLRelease(pkey); PLRelease(pvalue);
    g_free(strval);
    return prop;
}

proplist_t config_set_bool(proplist_t prop, gchar *key, gboolean value)
{
    proplist_t pkey, pvalue;

    pkey = PLMakeString(key); pvalue = PLMakeString(value ? "Yes" : "No");
    prop = PLInsertDictionaryEntry(prop, pkey, pvalue);
    PLRelease(pkey); PLRelease(pvalue);
    return prop;
}

proplist_t config_clean_key(proplist_t prop, gchar *key)
{
    proplist_t pkey;

    pkey = PLMakeString(key);
    PLRemoveDictionaryEntry(prop, pkey);
    PLRelease(pkey);
    return prop;
}

proplist_t config_section(proplist_t prop, gchar *section)
{
    proplist_t ret, pkey, psect;

    pkey = PLMakeString(section);
    ret = PLGetDictionaryEntry(prop, pkey);
    if (ret == NULL)
    {
	psect = PLMakeDictionaryFromEntries(NULL, NULL);
	prop = PLInsertDictionaryEntry(prop, pkey, psect);
	ret = PLGetDictionaryEntry(prop, pkey);
    }
    PLRelease(pkey);

    return ret;
}

proplist_t config_list_section(proplist_t prop, gchar *section)
{
    proplist_t ret, pkey, psect;

    pkey = PLMakeString(section);
    ret = PLGetDictionaryEntry(prop, pkey);
    if (ret == NULL)
    {
	psect = PLMakeArrayFromElements(NULL);
	prop = PLInsertDictionaryEntry(prop, pkey, psect);
	ret = PLGetDictionaryEntry(prop, pkey);
    }
    PLRelease(pkey);

    return ret;
}

gint config_list_find(proplist_t prop, gchar *key, gchar *value)
{
    proplist_t item;
    gint num, max;
    gchar *ret;

    if (prop == NULL)
	return -1;

    max = PLGetNumberOfElements(prop);
    for (num = 0; num < max; num++)
    {
	item = PLGetArrayElement(prop, num);
	ret = config_get_str(item, key, NULL);
	if (ret != NULL && g_strcasecmp(ret, value) == 0)
	    return num;
    }

    return -1;
}

