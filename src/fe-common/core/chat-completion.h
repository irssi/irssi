#ifndef __CHAT_COMPLETION_H
#define __CHAT_COMPLETION_H

void completion_last_message_add(const char *nick);
void completion_last_message_remove(const char *nick);
void completion_last_message_rename(const char *oldnick, const char *newnick);

#endif
