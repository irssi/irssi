#ifndef __TRANSLATION_H
#define __TRANSLATION_H

extern unsigned char translation_in[256], translation_out[256];

int translation_read(const char *file);
void translate_output(char *text);

void translation_init(void);
void translation_deinit(void);

#endif
