#ifndef __CHAT_COMPLETION_H
#define __CHAT_COMPLETION_H

GList *completion_get_chatnets(const char *word);
GList *completion_get_servers(const char *word);
GList *completion_get_servertags(const char *word);
GList *completion_get_channels(SERVER_REC *server, const char *word);
GList *completion_get_aliases(const char *word);

void completion_last_message_add(const char *nick);
void completion_last_message_remove(const char *nick);
void completion_last_message_rename(const char *oldnick, const char *newnick);

#endif
