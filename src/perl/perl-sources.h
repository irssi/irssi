#ifndef __PERL_SOURCES_H
#define __PERL_SOURCES_H

int perl_timeout_add(int msecs, const char *func, SV *data);
int perl_input_add(int source, int condition, const char *func, SV *data);

void perl_source_remove(int tag);
/* remove all sources used by package */
void perl_source_remove_package(const char *package);

void perl_sources_start(void);
void perl_sources_stop(void);

#endif
