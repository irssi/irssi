#ifndef __MODES_H
#define __MODES_H

#include "irc-servers.h"
#include "irc-channels.h"

/* modes that have argument always */
#define HAS_MODE_ARG_ALWAYS(mode) \
	((mode) == 'b' || (mode) == 'e' || (mode) == 'I' || \
	(mode) == 'o' || (mode) == 'h' || (mode) == 'v' || (mode) == 'k')

/* modes that have argument when being set (+) */
#define HAS_MODE_ARG_SET(mode) \
	(HAS_MODE_ARG_ALWAYS(mode) || (mode) == 'l')

/* modes that have argument when being unset (-) */
#define HAS_MODE_ARG_UNSET(mode) \
	HAS_MODE_ARG_ALWAYS(mode)

#define HAS_MODE_ARG(type, mode) \
	((type) == '+' ? HAS_MODE_ARG_SET(mode) : HAS_MODE_ARG_UNSET(mode))

void modes_init(void);
void modes_deinit(void);

/* add `mode' to `old' - return newly allocated mode. */
char *modes_join(const char *old, const char *mode);

int channel_mode_is_set(IRC_CHANNEL_REC *channel, char mode);

void parse_channel_modes(IRC_CHANNEL_REC *channel, const char *setby,
			 const char *modestr);

void channel_set_singlemode(IRC_SERVER_REC *server, const char *channel,
			    const char *nicks, const char *mode);
void channel_set_mode(IRC_SERVER_REC *server, const char *channel,
		      const char *mode);

#endif
