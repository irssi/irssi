#ifndef __FE_COMMON_CORE_H
#define __FE_COMMON_CORE_H

void fe_common_core_register_options(void);
void fe_common_core_init(void);
void fe_common_core_deinit(void);
void fe_common_core_finish_init(void);

/* Returns TRUE if "dest->target" or "dest->server_tag/dest->target" is found in
 * array, otherwise FALSE. */
gboolean strarray_find_dest(char **array, const TEXT_DEST_REC *dest);

#endif
