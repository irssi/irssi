#ifndef IRSSI_CORE_MODULES_LOAD_H
#define IRSSI_CORE_MODULES_LOAD_H

#include <irssi/src/core/modules.h>

/* Load module - automatically tries to load also the related non-core
   modules given in `prefixes' (like irc, fe, fe_text, ..) */
int module_load(const char *path, char **prefixes);

/* Load a sub module. */
int module_load_sub(const char *path, const char *submodule, char **prefixes);

void module_unload(MODULE_REC *module);
void module_file_unload(MODULE_FILE_REC *file);

#endif
