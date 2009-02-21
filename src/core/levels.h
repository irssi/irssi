#ifndef __LEVELS_H
#define __LEVELS_H

/* This is pretty much IRC specific, but I think it would be easier for
   other chats to try to use these same levels instead of implementing too
   difficult message leveling system (which might be done if really
   needed..). */

/* Message levels */
enum {
	MSGLEVEL_CRAP         = 0x0000001,
	MSGLEVEL_MSGS         = 0x0000002,
	MSGLEVEL_PUBLIC       = 0x0000004,
	MSGLEVEL_NOTICES      = 0x0000008,
	MSGLEVEL_SNOTES       = 0x0000010,
	MSGLEVEL_CTCPS        = 0x0000020,
	MSGLEVEL_ACTIONS      = 0x0000040,
	MSGLEVEL_JOINS        = 0x0000080,
	MSGLEVEL_PARTS        = 0x0000100,
	MSGLEVEL_QUITS        = 0x0000200,
	MSGLEVEL_KICKS        = 0x0000400,
	MSGLEVEL_MODES        = 0x0000800,
	MSGLEVEL_TOPICS       = 0x0001000,
	MSGLEVEL_WALLOPS      = 0x0002000,
	MSGLEVEL_INVITES      = 0x0004000,
	MSGLEVEL_NICKS        = 0x0008000,
	MSGLEVEL_DCC          = 0x0010000,
	MSGLEVEL_DCCMSGS      = 0x0020000,
	MSGLEVEL_CLIENTNOTICE = 0x0040000,
	MSGLEVEL_CLIENTCRAP   = 0x0080000,
	MSGLEVEL_CLIENTERROR  = 0x0100000,
	MSGLEVEL_HILIGHT      = 0x0200000,

	MSGLEVEL_ALL          = 0x03fffff,

	MSGLEVEL_NOHILIGHT    = 0x1000000, /* Don't highlight this message */
	MSGLEVEL_NO_ACT       = 0x2000000, /* Don't trigger channel activity */
	MSGLEVEL_NEVER        = 0x4000000, /* never ignore / never log */
	MSGLEVEL_LASTLOG      = 0x8000000 /* never ignore / never log */
};

int level_get(const char *level);
int level2bits(const char *level, int *errorp);
char *bits2level(int bits);
int combine_level(int dest, const char *src);

#endif
