#include "common.h"

#define MODULE_NAME "fe-common/core"

typedef guint32 unichar;
typedef struct {
	time_t time;
	char *nick;

	/* channel specific msg to/from me - this is actually a reference
	   count. it begins from `completion_keep_publics' and is decreased
	   every time some nick is added to lastmsgs list.

	   this is because of how the nick completion works. the same nick
	   is never in the lastmsgs list twice, but every time it's used
	   it's just moved to the beginning of the list. if this would be
	   just a boolean value the own-status would never be removed
	   from the nick if it didn't keep quiet for long enough.

	   so, the own-status is rememberd only for the last
           `completion_keep_publics' lines */
	int own;
} LAST_MSG_REC;

typedef struct {
	/* /MSG completion: */
	GSList *lastmsgs; /* list of nicks who sent you msg or
			     to who you send msg */
} MODULE_SERVER_REC;

typedef struct {
	/* nick completion: */
	GSList *lastmsgs; /* list of nicks who sent latest msgs and
			     list of nicks who you sent msgs to */
} MODULE_CHANNEL_REC;
