#ifndef IRSSI_IRC_CORE_SCRAM_H
#define IRSSI_IRC_CORE_SCRAM_H

#include <openssl/evp.h>

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
} SCRAM_SESSION_REC;

typedef enum { SCRAM_ERROR = 0, SCRAM_IN_PROGRESS, SCRAM_SUCCESS } scram_status;

SCRAM_SESSION_REC *scram_session_create(const char *digset, const char *username,
                                        const char *password);
void scram_session_free(SCRAM_SESSION_REC *session);
scram_status scram_process(SCRAM_SESSION_REC *session, const char *input, char **output,
                           size_t *output_len);

#endif
