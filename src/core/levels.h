#ifndef __LEVELS_H
#define __LEVELS_H

/* This is pretty much IRC specific, but I think it would be easier for
   other chats to try to use these same levels instead of implementing too
   difficult message leveling system (which might be done if really
   needed..). */

/* Message levels */
#define MSGLEVEL_CRAP         0x0000001
#define MSGLEVEL_MSGS         0x0000002
#define MSGLEVEL_PUBLIC       0x0000004
#define MSGLEVEL_NOTICES      0x0000008
#define MSGLEVEL_SNOTES       0x0000010
#define MSGLEVEL_CTCPS        0x0000020
#define MSGLEVEL_ACTIONS      0x0000040
#define MSGLEVEL_JOINS        0x0000080
#define MSGLEVEL_PARTS        0x0000100
#define MSGLEVEL_QUITS        0x0000200
#define MSGLEVEL_KICKS        0x0000400
#define MSGLEVEL_MODES        0x0000800
#define MSGLEVEL_TOPICS       0x0001000
#define MSGLEVEL_WALLOPS      0x0002000
#define MSGLEVEL_INVITES      0x0004000
#define MSGLEVEL_NICKS        0x0008000
#define MSGLEVEL_DCC          0x0010000
#define MSGLEVEL_DCCMSGS      0x0020000
#define MSGLEVEL_CLIENTNOTICE 0x0040000
#define MSGLEVEL_CLIENTCRAP   0x0080000
#define MSGLEVEL_CLIENTERROR  0x0100000
#define MSGLEVEL_HILIGHT      0x0200000

#define MSGLEVEL_ALL          0x03fffff

#define MSGLEVEL_NOHILIGHT    0x1000000 /* Don't highlight this message */
#define MSGLEVEL_NO_ACT       0x2000000 /* Don't trigger channel activity */
#define MSGLEVEL_NEVER        0x4000000 /* never ignore / never log */
#define MSGLEVEL_LASTLOG      0x8000000 /* never ignore / never log */

int level_get(const char *level);
int level2bits(const char *level);
char *bits2level(int bits);
int combine_level(int dest, const char *src);

#endif
