#ifndef __PERL_SOURCES_H
#define __PERL_SOURCES_H

int perl_timeout_add(int msecs, SV *func, SV *data, int once);
int perl_input_add(int source, int condition, SV *func, SV *data, int once);

void perl_source_remove(int tag);
/* remove all sources used by script */
void perl_source_remove_script(PERL_SCRIPT_REC *script);

void perl_sources_start(void);
void perl_sources_stop(void);

#endif
