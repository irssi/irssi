#ifndef IRSSI_CORE_REFSTRINGS_H
#define IRSSI_CORE_REFSTRINGS_H

#include <glib.h>

#if GLIB_CHECK_VERSION(2, 58, 0)

#define i_refstr_init() /* nothing */
#define i_refstr_release(str) ((str) == NULL ? NULL : g_ref_string_release(str))
#define i_refstr_intern(str) ((str) == NULL ? NULL : g_ref_string_new_intern(str))
#define i_refstr_deinit() /* nothing */
#define i_refstr_table_size_info() NULL

#else

void i_refstr_init(void);
char *i_refstr_intern(const char *str);
void i_refstr_release(char *str);
void i_refstr_deinit(void);
char *i_refstr_table_size_info(void);

#endif

#endif
