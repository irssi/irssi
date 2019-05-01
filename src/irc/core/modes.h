#ifndef IRSSI_IRC_CORE_MODES_H
#define IRSSI_IRC_CORE_MODES_H

#include <irssi/src/irc/core/irc-channels.h>
#include <irssi/src/core/nicklist.h> /* MAX_USER_PREFIXES */

typedef void mode_func_t(IRC_CHANNEL_REC *, const char *, char, char,
			 char *, GString *);

struct modes_type {
	mode_func_t *func;
	char prefix;
};

/* modes that have argument always */
#define HAS_MODE_ARG_ALWAYS(server, mode) \
   (server->modes[(int)(unsigned char) mode].func == modes_type_a || \
    server->modes[(int)(unsigned char) mode].func == modes_type_b || \
    server->modes[(int)(unsigned char) mode].func == modes_type_prefix)

/* modes that have argument when being set (+) */
#define HAS_MODE_ARG_SET(server, mode) \
	(HAS_MODE_ARG_ALWAYS(server, mode) || \
	  server->modes[(int)(unsigned char) mode].func == modes_type_c)

/* modes that have argument when being unset (-) */
#define HAS_MODE_ARG_UNSET(server, mode) \
	HAS_MODE_ARG_ALWAYS(server, mode)

#define HAS_MODE_ARG(server, type, mode) \
	((type) == '+' ? HAS_MODE_ARG_SET(server,mode) : \
	  HAS_MODE_ARG_UNSET(server, mode))

#define GET_MODE_PREFIX(server, c) \
	((server)->modes[(int)(unsigned char)c].prefix)
#define GET_PREFIX_MODE(server, c) \
	((server)->prefix[(int)(unsigned char)c])

void modes_init(void);
void modes_deinit(void);
void modes_server_init(IRC_SERVER_REC *);

/* add `mode' to `old' - return newly allocated mode.
   `channel' specifies if we're parsing channel mode and we should try
   to join mode arguments too. */
char *modes_join(IRC_SERVER_REC *server, const char *old, const char *mode, int channel);

int channel_mode_is_set(IRC_CHANNEL_REC *channel, char mode);

void parse_channel_modes(IRC_CHANNEL_REC *channel, const char *setby,
			 const char *modestr, int update_key);

void channel_set_singlemode(IRC_CHANNEL_REC *channel, const char *nicks,
			    const char *mode);
void channel_set_mode(IRC_SERVER_REC *server, const char *channel,
		      const char *mode);

void prefix_add(char prefixes[MAX_USER_PREFIXES+1], char newprefix, SERVER_REC *server);
void prefix_del(char prefixes[MAX_USER_PREFIXES+1], char oldprefix);

mode_func_t modes_type_a;
mode_func_t modes_type_b;
mode_func_t modes_type_c;
mode_func_t modes_type_d;
mode_func_t modes_type_prefix;

#endif
