#ifndef __RECODE_H
#define __RECODE_H

char *recode_in (const char *str, const char *target);
char *recode_out (const char *str, const char *target);
gboolean is_valid_charset(const char *charset);

void recode_init (void);
void recode_deinit (void);

#endif /* __RECODE_H */
