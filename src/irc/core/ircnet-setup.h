#ifndef __IRCNET_SETUP_H
#define __IRCNET_SETUP_H

typedef struct {
	char *name;

	char *nick;
	char *username;
	char *realname;

        char *own_host; /* address to use when connecting this server */
	IPADDR *own_ip; /* resolved own_address if not NULL */

	int max_cmds_at_once;
	int cmd_queue_speed;

	/* max. number of kicks/msgs/mode/whois per command */
	int max_kicks, max_msgs, max_modes, max_whois;
} IRCNET_REC;

extern GSList *ircnets; /* list of available ircnets */

void ircnet_create(IRCNET_REC *ircnet);
void ircnet_destroy(IRCNET_REC *ircnet);

/* Find the irc network by name */
IRCNET_REC *ircnet_find(const char *name);

void ircnets_setup_init(void);
void ircnets_setup_deinit(void);

#endif
