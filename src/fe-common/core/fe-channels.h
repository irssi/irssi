#ifndef __FE_CHANNELS_H
#define __FE_CHANNELS_H

#define CHANNEL_NICKLIST_FLAG_OPS       0x01
#define CHANNEL_NICKLIST_FLAG_HALFOPS   0x02
#define CHANNEL_NICKLIST_FLAG_VOICES    0x04
#define CHANNEL_NICKLIST_FLAG_NORMAL    0x08
#define CHANNEL_NICKLIST_FLAG_ALL       0x0f
#define CHANNEL_NICKLIST_FLAG_COUNT     0x10

void fe_channels_nicklist(CHANNEL_REC *channel, int flags);

void fe_channels_init(void);
void fe_channels_deinit(void);

#endif
