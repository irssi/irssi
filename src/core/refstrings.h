#ifndef IRSSI_CORE_REFSTRINGS_H
#define IRSSI_CORE_REFSTRINGS_H

void i_refstr_init(void);
char *i_refstr_intern(const char *str);
void i_refstr_release(char *str);
void i_refstr_deinit(void);
char *i_refstr_table_size_info(void);

#endif
