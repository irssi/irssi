#ifndef IRSSI_CORE_WRITE_BUFFER_H
#define IRSSI_CORE_WRITE_BUFFER_H

int write_buffer(int handle, const void *data, int size);
void write_buffer_flush(void);

void write_buffer_init(void);
void write_buffer_deinit(void);

#endif
