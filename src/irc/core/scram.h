#ifndef IRSSI_IRC_CORE_SCRAM_H
#define IRSSI_IRC_CORE_SCRAM_H

#include <openssl/evp.h>

#define SCRAM_ERROR			0
#define SCRAM_IN_PROGRESS	1
#define SCRAM_SUCCESS		2

typedef struct {
	const EVP_MD *digest;
	size_t digest_size;
	char *username;
	char *password;
	char *client_nonce_b64;
	char *client_first_message_bare;
	unsigned char *salted_password;
	char *auth_message;
	char *error;
	int step;
} scram_session;

scram_session *scram_create_session(const char *digset, const char *username, const char *password);
void scram_free_session(scram_session *session);
int scram_process(scram_session *session, const char *input, char **output, size_t *output_len);

#endif