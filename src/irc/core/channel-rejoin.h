#ifndef __CHANNEL_REJOIN_H
#define __CHANNEL_REJOIN_H

typedef struct {
	char *channel;
	char *key;
	unsigned int joining:1;
} REJOIN_REC;

void channel_rejoin_init(void);
void channel_rejoin_deinit(void);

#endif
