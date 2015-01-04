/*
 * Off-the-Record Messaging (OTR) modules for IRC
 *
 * Copyright (C) 2008 - Uli Meis <a.sporto+bee@gmail.com>
 *               2012 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef IRSSI_OTR_OTR_H
#define IRSSI_OTR_OTR_H

/* Libotr */
#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/context.h>
#include <libotr/privkey.h>

#include "common.h"
#include "servers.h"

/* irssi module name */
#define MODULE_NAME                   "otr/core"

/*
 * XXX: Maybe this should be configurable?
 */
#define OTR_MAX_MSG_SIZE              400

/* OTR protocol id */
#define OTR_PROTOCOL_ID               "IRC"

#define OTR_DIR                       "otr"
#define OTR_KEYFILE                   OTR_DIR "/otr.key"
#define OTR_FINGERPRINTS_FILE         OTR_DIR "/otr.fp"
#define OTR_INSTAG_FILE               OTR_DIR "/otr.instag"

/*
 * Specified in OTR protocol version 3. See:
 * http://www.cypherpunks.ca/otr/Protocol-v3-4.0.0.html
 */
#define OTR_MSG_BEGIN_TAG             "?OTR:"
#define OTR_MSG_END_TAG               '.'

/* IRC /me command marker and len. */
#define OTR_IRC_MARKER_ME             "/me "
#define OTR_IRC_MARKER_ME_LEN         sizeof(OTR_IRC_MARKER_ME) - 1

/* Irssi otr user state */
struct otr_user_state {
	OtrlUserState otr_state;
};

/*
 * Peer OTR internal context.
 */
struct otr_peer_context {
	/* The SMP event status. Used for the Irssi status bar. */
	OtrlSMPEvent smp_event;
	/* Did the SMP secret was asked so are we in a responder state? */
	unsigned int ask_secret;
	/*
	 * The fingerprint of the private message OTR session. This is useful for
	 * the forget command for which we can recover the fingerprint
	 * automatically.
	 */
	Fingerprint *active_fingerprint;
	/*
	 * If needed, used to reconstruct the full message from fragmentation.
	 * Bitlbee for instance does that where we receive a *long* OTR message
	 * split in multiple PRIVMSG so we need to reconstruct it.
	 */
	char *full_msg;
	/* Size of full_msg. Note this is the allocated memory size. */
	size_t msg_size;
	/* Len of the actual string in full_msg NOT counting the NULL byte. */
	size_t msg_len;
};

/* given to otr_status_change */
enum otr_status_event {
	OTR_STATUS_FINISHED,
	OTR_STATUS_TRUST_MANUAL,
	OTR_STATUS_TRUST_SMP,
	OTR_STATUS_SMP_ABORT,
	OTR_STATUS_SMP_STARTED,
	OTR_STATUS_SMP_RESPONDED,
	OTR_STATUS_SMP_INCOMING,
	OTR_STATUS_SMP_FINALIZE,
	OTR_STATUS_SMP_ABORTED,
	OTR_STATUS_PEER_FINISHED,
	OTR_STATUS_SMP_FAILED,
	OTR_STATUS_SMP_SUCCESS,
	OTR_STATUS_GONE_SECURE,
	OTR_STATUS_GONE_INSECURE,
	OTR_STATUS_CTX_UPDATE
};

enum otr_msg_status {
	OTR_MSG_ORIGINAL		= 1,
	OTR_MSG_WAIT_MORE		= 2,
	OTR_MSG_USE_QUEUE		= 3,
	OTR_MSG_ERROR			= 4,
};

/* there can be only one */
extern struct otr_user_state *user_state_global;

/* Libotr ops functions */
extern OtrlMessageAppOps otr_ops;

/* Active debug or not */
extern int debug;

void irssi_send_message(SERVER_REC *irssi, const char *recipient,
		const char *message);
void otr_status_change(SERVER_REC *irssi, const char *nick,
		enum otr_status_event event);

/* init stuff */

struct otr_user_state *otr_init_user_state(void);
void otr_free_user_state(struct otr_user_state *ustate);

void otr_lib_init();
void otr_lib_uninit();

void otr_control_timer(unsigned int interval, void *opdata);

/* Message transport. */
int otr_send(SERVER_REC *irssi, const char *msg, const char *to,
		char **otr_msg);
int otr_receive(SERVER_REC *irssi, const char *msg,
		const char *from, char **new_msg);

/* User interaction */
void otr_finish(SERVER_REC *irssi, const char *nick);
void otr_auth(SERVER_REC *irssi, const char *nick, const char *question,
		const char *secret);
void otr_auth_abort(SERVER_REC *irssi, const char *nick);
void otr_contexts(struct otr_user_state *ustate);
void otr_finishall(struct otr_user_state *ustate);
void otr_forget(SERVER_REC *irssi, const char *nick, char *str_fp,
		struct otr_user_state *ustate);
void otr_distrust(SERVER_REC *irssi, const char *nick, char *str_fp,
		struct otr_user_state *ustate);
void otr_trust(SERVER_REC *irssi, const char *nick, char *str_fp,
		struct otr_user_state *ustate);

enum otr_status_format otr_get_status_format(SERVER_REC *irssi,
		const char *nick);

struct otr_peer_context *otr_create_peer_context(void);
ConnContext *otr_find_context(SERVER_REC *irssi, const char *nick, int create);
Fingerprint *otr_find_hash_fingerprint_from_human(const char *human_fp,
		struct otr_user_state *ustate);

#endif /* IRSSI_OTR_OTR_H */
