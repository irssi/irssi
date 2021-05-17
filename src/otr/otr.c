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

#define _GNU_SOURCE
#include <glib.h>
#include <gcrypt.h>
#include <unistd.h>

#include <irssi/src/common.h>
#include <irssi/src/core/levels.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/fe-common/core/printtext.h>
#include <irssi/src/fe-text/statusbar-item.h>

#include <irssi/src/otr/irssi-otr.h>
#include <irssi/src/otr/otr-formats.h>
#include <irssi/src/otr/key.h>

static int otr_debug = 0;

static const char *statusbar_txt[] = {
	"FINISHED",
	"TRUST_MANUAL",
	"TRUST_SMP",
	"SMP_ABORT",
	"SMP_STARTED",
	"SMP_RESPONDED",
	"SMP_INCOMING",
	"SMP_FINALIZE",
	"SMP_ABORTED",
	"PEER_FINISHED",
	"SMP_FAILED",
	"SMP_SUCCESS",
	"GONE_SECURE",
	"GONE_INSECURE",
	"CTX_UPDATE"
};

/* Glib timer for otr. */
static guint otr_timerid;

/*
 * Load instance tags.
 */
static void instag_load(struct otr_user_state *ustate)
{
	int ret;
	char *filename;
	gcry_error_t err;

	g_return_if_fail(ustate != NULL);

	/* Getting the otr instance filename path */
	filename = g_strdup_printf("%s%s", get_irssi_dir(), OTR_INSTAG_FILE);
	g_return_if_fail(filename != NULL);

	ret = access(filename, F_OK);
	if (ret < 0) {
		IRSSI_OTR_DEBUG("no instance tags found at %9%s%9", filename);
		g_free(filename);
		return;
	}

	err = otrl_instag_read(ustate->otr_state, filename);
	if (err == GPG_ERR_NO_ERROR)
		IRSSI_OTR_DEBUG("Instance tags loaded from %9%s%9", filename);
	else
		IRSSI_OTR_DEBUG("Error loading instance tags: %d (%d)", gcry_strerror(err), gcry_strsource(err));

	g_free(filename);
}

/*
 * Free otr peer context. Callback passed to libotr.
 */
static void free_peer_context_cb(void *data)
{
	g_free_not_null(data);
}

/*
 * Allocate otr peer context. Callback passed to libotr.
 */
static void add_peer_context_cb(void *data, ConnContext *context)
{
	struct otr_peer_context *opc;

	opc = otr_create_peer_context();
	if (opc == NULL) {
		return;
	}

	opc->active_fingerprint = context->active_fingerprint;

	context->app_data = opc;
	context->app_data_free = free_peer_context_cb;

	IRSSI_OTR_DEBUG("Peer context created for %s", context->username);
}

/*
 * Find Irssi server record by network name.
 */
static SERVER_REC *find_server_by_network(const char *network)
{
	GSList *tmp;
	SERVER_REC *server;

	g_return_val_if_fail(network != NULL, NULL);

	for (tmp = servers; tmp; tmp = tmp->next) {
		server = tmp->data;

		if (g_ascii_strncasecmp(server->tag, network, strlen(server->tag)))
			return server;
	}

	return NULL;
}

/*
 * Check if fingerprint is in an encrypted context.
 *
 * Return 1 if it does, else 0.
 */
static int check_fp_encrypted_msgstate(Fingerprint *fp)
{
	ConnContext *context;

	g_return_val_if_fail(fp != NULL, 0);

	/* Loop on all fingerprint's context(es). */
	for (context = fp->context;
			context != NULL && context->m_context == fp->context;
			context = context->next) {
		if (context->msgstate == OTRL_MSGSTATE_ENCRYPTED &&
				context->active_fingerprint == fp) {
			return 1;
		}
	}

	/* No state is encrypted. */
	return 0;
}

/*
 * Timer called from the glib main loop and set up by the timer_control
 * callback of libotr.
 */
static gboolean timer_fired_cb(gpointer data)
{
	otrl_message_poll(user_state_global->otr_state, &otr_ops, NULL);
	return TRUE;
}

void otr_control_timer(unsigned int interval, void *opdata)
{
	if (otr_timerid) {
		g_source_remove(otr_timerid);
		otr_timerid = 0;
	}

	if (interval > 0) {
		otr_timerid = g_timeout_add_seconds(interval, timer_fired_cb, opdata);
	}
}

/*
 * Is OTR debugging enabled or disabled?
 */
int otr_debug_get(void)
{
    return otr_debug;
}

/*
 * Toggle OTR debugging.
 */
void otr_debug_toggle(void)
{
    otr_debug = !otr_debug;
}

/*
 * Find context from nickname and irssi server record.
 */
ConnContext *otr_find_context(SERVER_REC *server, const char *nick, int create)
{
	ConnContext *ctx = NULL;

	g_return_val_if_fail(server != NULL, NULL);
	g_return_val_if_fail(server->tag != NULL, NULL);
	g_return_val_if_fail(nick != NULL, NULL);

	ctx = otrl_context_find(user_state_global->otr_state, nick, server->tag,
			OTR_PROTOCOL_ID, OTRL_INSTAG_BEST, create, NULL,
			add_peer_context_cb, server);

	return ctx;
}

/*
 * Create otr peer context.
 */
struct otr_peer_context *otr_create_peer_context(void)
{
	return g_new0(struct otr_peer_context, 1);
}

/*
 * Return a newly allocated OTR user state.
 */
struct otr_user_state *otr_init_user_state(void)
{
	struct otr_user_state *ous = NULL;

	ous = g_new0(struct otr_user_state, 1);
	if (ous == NULL) {
		return ous;
	}

	ous->otr_state = otrl_userstate_create();

	instag_load(ous);

	/* Load keys and fingerprints. */
	key_load(ous);
	key_load_fingerprints(ous);

	return ous;
}

/*
 * Destroy otr user state.
 */
void otr_free_user_state(struct otr_user_state *ustate)
{
	if (ustate->otr_state) {
		otrl_userstate_free(ustate->otr_state);
		ustate->otr_state = NULL;
	}

	g_free(ustate);
}

/*
 * init otr lib.
 */
void otr_lib_init()
{
	OTRL_INIT;
}

/*
 * deinit otr lib.
 */
void otr_lib_uninit()
{
}

/*
 * Hand the given message to OTR.
 *
 * Return 0 if the message was successfully handled or else a negative value.
 */
int otr_send(SERVER_REC *server, const char *msg, const char *to, char **otr_msg)
{
	gcry_error_t err;
	ConnContext *ctx = NULL;

	g_return_val_if_fail(server != NULL, -1);
	g_return_val_if_fail(server->tag != NULL, -1);

	IRSSI_OTR_DEBUG("OTR: Sending message: %s", msg);

	err = otrl_message_sending(user_state_global->otr_state, &otr_ops,
		server, server->tag, OTR_PROTOCOL_ID, to, OTRL_INSTAG_BEST, msg, NULL, otr_msg,
		OTRL_FRAGMENT_SEND_ALL_BUT_LAST, &ctx, add_peer_context_cb, server);
	if (err) {
		g_warning("OTR: Send failed: %s", gcry_strerror(err));
		return -1;
	}

	/* Add peer context to OTR context if none exists. */
	if (ctx && !ctx->app_data) {
		add_peer_context_cb(server, ctx);
	}

	return 0;
}

/*
 * List otr contexts to the main Irssi windows.
 */
void otr_contexts(struct otr_user_state *ustate)
{
	char human_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN], *trust;
	ConnContext *ctx, *c_iter;
	Fingerprint *fp;

	g_return_if_fail(ustate != NULL);

	if (ustate->otr_state->context_root == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR, TXT_OTR_CTX_MISSING);
		return;
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_OTR_CTX_LIST_HEADER);

	/* Iterate over all contextes of the user state. */
	for (ctx = ustate->otr_state->context_root; ctx != NULL; ctx = ctx->next) {
		OtrlMessageState best_mstate = OTRL_MSGSTATE_PLAINTEXT;

		/* Skip master context. */
		if (ctx != ctx->m_context)
			continue;

		for (fp = ctx->fingerprint_root.next; fp != NULL; fp = fp->next) {
			int used = 0;
			char *username, *accountname;

			username = ctx->username;
			accountname = ctx->accountname;

			for (c_iter = ctx->m_context; c_iter && c_iter->m_context == ctx->m_context; c_iter = c_iter->next) {
				/* Print account name, username and msgstate. */
				if (c_iter->active_fingerprint == fp) {
					used = 1;

					if (c_iter->msgstate == OTRL_MSGSTATE_ENCRYPTED)
						best_mstate = OTRL_MSGSTATE_ENCRYPTED;
					else if (c_iter->msgstate == OTRL_MSGSTATE_FINISHED && best_mstate == OTRL_MSGSTATE_PLAINTEXT)
						best_mstate = OTRL_MSGSTATE_FINISHED;
				}
			}

			if (used) {
				switch (best_mstate) {
					case OTRL_MSGSTATE_ENCRYPTED:
						printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_OTR_CTX_LIST_ENCRYPTED_LINE, accountname, username);
						break;
					case OTRL_MSGSTATE_PLAINTEXT:
						printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_OTR_CTX_LIST_PLAINTEXT_LINE, accountname, username);
						break;
					case OTRL_MSGSTATE_FINISHED:
						printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_OTR_CTX_LIST_FINISHED_LINE, accountname, username);
						break;
					default:
						printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_OTR_CTX_LIST_UNKNOWN_LINE, accountname, username);
						break;
				};
			} else
				printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_OTR_CTX_LIST_UNUSED_LINE, accountname, username);

			/* Hash fingerprint to human. */
			otrl_privkey_hash_to_human(human_fp, fp->fingerprint);

			trust = fp->trust;
			if (trust && trust[0] != '\0') {
				if (strncmp(trust, "smp", 3) == 0)
					printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_OTR_CTX_LIST_SMP_LINE, human_fp);
				else
					printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_OTR_CTX_LIST_MANUAL_LINE, human_fp);
			} else
				printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_OTR_CTX_LIST_UNVERIFIED_LINE, human_fp);
		}
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, TXT_OTR_CTX_LIST_FOOTER);
}

/*
 * Finish the conversation.
 */
void otr_finish(SERVER_REC *server, const char *nick)
{
	ConnContext *ctx;

	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

	ctx = otr_find_context(server, nick, FALSE);
	if (ctx == NULL) {
		printformat(server, nick, MSGLEVEL_CRAP, TXT_OTR_SESSION_ALREADY_FINISHED);
		return;
	}

	otrl_message_disconnect(user_state_global->otr_state, &otr_ops, server,
			ctx->accountname, OTR_PROTOCOL_ID, nick, ctx->their_instance);

	otr_status_change(server, nick, OTR_STATUS_FINISHED);

	printformat(server, nick, MSGLEVEL_CRAP, TXT_OTR_SESSION_FINISHING, nick);
}

/*
 * Finish all otr contexts.
 */
void otr_finishall(struct otr_user_state *ustate)
{
	ConnContext *context;
	SERVER_REC *server;

	g_return_if_fail(ustate != NULL);

	for (context = ustate->otr_state->context_root; context;
			context = context->next) {
		/* Only finish encrypted session. */
		if (context->msgstate != OTRL_MSGSTATE_ENCRYPTED) {
			continue;
		}

		server = find_server_by_network(context->accountname);
		if (server == NULL) {
			IRSSI_OTR_DEBUG("Unable to find server window for account %s", context->accountname);
			continue;
		}

		otr_finish(server, context->username);
	}
}

/*
 * Trust our peer.
 */
void otr_trust(SERVER_REC *server, const char *nick, char *str_fp,
		struct otr_user_state *ustate)
{
	char peerfp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	struct otr_peer_context *opc;
	ConnContext *ctx;
	Fingerprint *fp_trust;

	g_return_if_fail(ustate != NULL);

	/* No human string fingerprint given. */
	if (*str_fp == '\0') {
		ctx = otr_find_context(server, nick, FALSE);
		if (ctx == NULL) {
			return;
		}

		opc = ctx->app_data;
		/* Always NEED a peer context or else code error. */
		g_return_if_fail(opc != NULL);

		fp_trust = ctx->active_fingerprint;
	} else {
		fp_trust = otr_find_hash_fingerprint_from_human(str_fp, ustate);
	}

	if (fp_trust != NULL) {
		otrl_privkey_hash_to_human(peerfp, fp_trust->fingerprint);

		if (otrl_context_is_fingerprint_trusted(fp_trust)) {
			printformat(server, nick, MSGLEVEL_CLIENTERROR, TXT_OTR_FP_ALREADY_TRUSTED, peerfp);
			return;
		}

		/* Trust level is manual at this point. */
		otrl_context_set_trust(fp_trust, "manual");
		key_write_fingerprints(ustate);

		otr_status_change(server, nick, OTR_STATUS_TRUST_MANUAL);

		printformat(server, nick, MSGLEVEL_CLIENTCRAP, TXT_OTR_FP_TRUSTED, peerfp);
	} else
		printformat(server, nick, MSGLEVEL_CLIENTERROR, TXT_OTR_FP_MISSING, str_fp);
}

/*
 * implements /otr authabort
 */
void otr_auth_abort(SERVER_REC *server, const char *nick)
{
	ConnContext *ctx;

	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

	ctx = otr_find_context(server, nick, FALSE);
	if (ctx == NULL) {
		printformat(server, nick, MSGLEVEL_CLIENTERROR, TXT_OTR_CTX_NICK_MISSING, nick);
		return;
	}

	otrl_message_abort_smp(user_state_global->otr_state, &otr_ops, server, ctx);
	otr_status_change(server, nick, OTR_STATUS_SMP_ABORT);

	if (ctx->smstate->nextExpected != OTRL_SMP_EXPECT1)
		printformat(server, nick, MSGLEVEL_CLIENTCRAP, TXT_OTR_AUTH_ONGOING_ABORTED);
	else
		printformat(server, nick, MSGLEVEL_CLIENTCRAP, TXT_OTR_AUTH_ABORTED);
}

/*
 * Initiate or respond to SMP authentication.
 */
void otr_auth(SERVER_REC *server, const char *nick, const char *question,
		const char *secret)
{
	int ret;
	size_t secret_len = 0;
	ConnContext *ctx;
	struct otr_peer_context *opc;

	g_return_if_fail(server != NULL);
	g_return_if_fail(nick != NULL);

	ctx = otr_find_context(server, nick, 0);
	if (ctx == NULL) {
		printformat(server, nick, MSGLEVEL_CLIENTERROR, TXT_OTR_CTX_NICK_MISSING, nick);
		return;
	}

	opc = ctx->app_data;
	/* Again, code flow error. */
	g_return_if_fail(opc != NULL);

	if (ctx->msgstate != OTRL_MSGSTATE_ENCRYPTED) {
		printformat(server, nick, MSGLEVEL_CLIENTERROR, TXT_OTR_SESSION_MISSING);
		return;
	}

	/* Aborting an ongoing auth */
	if (ctx->smstate->nextExpected != OTRL_SMP_EXPECT1) {
		otr_auth_abort(server, nick);
	}

	/* reset trust level */
	if (ctx->active_fingerprint) {
		ret = otrl_context_is_fingerprint_trusted(ctx->active_fingerprint);
		if (!ret) {
			otrl_context_set_trust(ctx->active_fingerprint, "");
			key_write_fingerprints(user_state_global);
		}
	}

	/* Libotr allows empty secret. */
	if (secret) {
		secret_len = strlen(secret);
	}

	if (opc->ask_secret) {
		otrl_message_respond_smp(user_state_global->otr_state, &otr_ops,
				server, ctx, (unsigned char *) secret, secret_len);
		otr_status_change(server, nick, OTR_STATUS_SMP_RESPONDED);
		printformat(server, nick, MSGLEVEL_CLIENTCRAP, TXT_OTR_AUTH_RESPONSE);
	} else {
		if (question != NULL)
			otrl_message_initiate_smp_q(user_state_global->otr_state, &otr_ops, server, ctx, question, (unsigned char *) secret, secret_len);
		else
			otrl_message_initiate_smp(user_state_global->otr_state, &otr_ops, server, ctx, (unsigned char *) secret, secret_len);

		otr_status_change(server, nick, OTR_STATUS_SMP_STARTED);
		printformat(server, nick, MSGLEVEL_CLIENTCRAP, TXT_OTR_AUTH_INITIATED);
	}

	opc->ask_secret = 0;
}

/*
 * For the given message we received through irssi, check if we need to queue
 * it for the case where that message is part of a bigger OTR full message.
 * This can happen with bitlbee for instance where OTR message are split in
 * different PRIVMSG.
 *
 * This uses a "queue" in the peer context so it's it very important to have
 * the peer context associated with the message (nickname + irssi object).
 *
 * Return an otr_msg_status code indicating the caller what to do with the msg.
 * OTR_MSG_ERROR indicates an error probably memory related. OTR_MSG_WAIT_MORE
 * tells the caller to NOT send out the message since we are waiting for more
 * to complete the OTR original message. OTR_MSG_ORIGINAL tell the caller to
 * simply use the original message. OTR_MSG_USE_QUEUE indicates that full_msg
 * can be used containing the reconstructed message. The caller SHOULD free(3)
 * this pointer after use.
 */
static enum otr_msg_status enqueue_otr_fragment(const char *msg, struct otr_peer_context *opc, char **full_msg)
{
	enum otr_msg_status ret;
	size_t msg_len;

	g_return_val_if_fail(msg != NULL, OTR_MSG_ERROR);
	g_return_val_if_fail(opc != NULL, OTR_MSG_ERROR);

	/* We are going to use it quite a bit so ease our life a bit. */
	msg_len = strlen(msg);

	if (opc->full_msg) {
		if (msg_len > (opc->msg_size - opc->msg_len)) {
			char *tmp_ptr;

			/* Realloc memory if there is not enough space. */
			tmp_ptr = realloc(opc->full_msg, opc->msg_size + msg_len + 1);
			if (tmp_ptr == NULL) {
				free(opc->full_msg);
				opc->full_msg = NULL;
				ret = OTR_MSG_ERROR;
				return ret;
			}
			opc->full_msg = tmp_ptr;
			opc->msg_size += msg_len + 1;
		}

		/* Copy msg to full message since we already have a part pending. Note
		 * that we do not copy `msg`'s trailing nul byte because we explicit
		 * set opc->full_msg[opc->msg_len] to nul afterwards. */
		memcpy(opc->full_msg + opc->msg_len, msg, msg_len);
		opc->msg_len += msg_len;
		opc->full_msg[opc->msg_len] = '\0';

		IRSSI_OTR_DEBUG("Partial OTR message added to queue: %s", msg);

		/*
		 * Are we waiting for more? If the message ends with a ".", the
		 * transmission has ended else we have to wait for more.
		 */
		if (msg[msg_len - 1] != OTR_MSG_END_TAG) {
			ret = OTR_MSG_WAIT_MORE;
			return ret;
		}

		/*
		 * Dup the string with enough space for the NULL byte since we are
		 * about to free it before passing it to the caller.
		 */
		*full_msg = g_strndup(opc->full_msg, opc->msg_len + 1);
		/* Reset everything. */
		free(opc->full_msg);
		opc->full_msg = NULL;
		opc->msg_size = opc->msg_len = 0;
		ret = OTR_MSG_USE_QUEUE;
		return ret;
	} else {
		char *pos;

		/*
		 * Try to find the OTR message tag at the _beginning_of the packet and
		 * check if this packet is not the end with the end tag of OTR "."
		 */
		pos = strstr(msg, OTR_MSG_BEGIN_TAG);
		if (pos && (pos == msg) && msg[msg_len - 1] != OTR_MSG_END_TAG) {
			/* Allocate full message buffer with an extra for NULL byte. */
			opc->full_msg = g_new0(char, (msg_len * 2) + 1);
			if (!opc->full_msg) {
				ret = OTR_MSG_ERROR;
				return ret;
			}
			/* Copy full message with NULL terminated byte. */
			memcpy(opc->full_msg, msg, msg_len);
			opc->msg_len += msg_len;
			opc->msg_size += ((msg_len * 2) + 1);
			opc->full_msg[opc->msg_len] = '\0';
			ret = OTR_MSG_WAIT_MORE;
			IRSSI_OTR_DEBUG("Partial OTR message begins the queue: %s", msg);
			return ret;
		}

		/* Use original message. */
		ret = OTR_MSG_ORIGINAL;
	}

	return ret;
}

/*
 * Hand the given message to OTR.
 *
 * Returns 0 if its an OTR protocol message or else negative value.
 */
int otr_receive(SERVER_REC *server, const char *msg, const char *from, char **new_msg)
{
	int ret = -1;
	char *full_msg = NULL;
	const char *recv_msg = NULL;
	OtrlTLV *tlvs;
	ConnContext *ctx;
	struct otr_peer_context *opc;
	OtrlTLV *tlv = NULL;

	g_return_val_if_fail(server != NULL, -1);
	g_return_val_if_fail(server->tag != NULL, -1);

	IRSSI_OTR_DEBUG("Receiving message: %s", msg);

	ctx = otr_find_context(server, from, 1);
	if (ctx == NULL) {
		return ret;
	}

	/* Add peer context to OTR context if none exists */
	if (ctx->app_data == NULL)
		add_peer_context_cb(server, ctx);

	opc = ctx->app_data;
	g_return_val_if_fail(opc != NULL, -1);

	ret = enqueue_otr_fragment(msg, opc, &full_msg);
	switch (ret) {
		case OTR_MSG_ORIGINAL:
			recv_msg = msg;
			break;
		case OTR_MSG_USE_QUEUE:
			recv_msg = full_msg;
			break;
		case OTR_MSG_WAIT_MORE:
			ret = 1;
			g_free_not_null(full_msg);
			return ret;
		case OTR_MSG_ERROR:
			ret = -1;
			g_free_not_null(full_msg);
			return ret;
	}

	ret = otrl_message_receiving(user_state_global->otr_state,
		&otr_ops, server, server->tag, OTR_PROTOCOL_ID, from, recv_msg, new_msg,
		&tlvs, &ctx, add_peer_context_cb, server);
	if (ret) {
		IRSSI_OTR_DEBUG("Ignoring message of length %d from %s to %s.\n%s", strlen(msg), from, server->tag, msg);
	} else {
		if (*new_msg) {
			IRSSI_OTR_DEBUG("Converted received message.");
		}
	}

	/* Check for disconnected message */
	tlv = otrl_tlv_find(tlvs, OTRL_TLV_DISCONNECTED);
	if (tlv != NULL) {
		otr_status_change(server, from, OTR_STATUS_PEER_FINISHED);
		printformat(server, from, MSGLEVEL_CLIENTCRAP, TXT_OTR_SESSION_FINISHED, from);
	}

	otrl_tlv_free(tlvs);

	IRSSI_OTR_DEBUG("Message received.");

	g_free_not_null(full_msg);

	return ret;
}

/*
 * Get the OTR status of this conversation.
 */
enum otr_status_format otr_get_status_format(SERVER_REC *server, const char *nick)
{
	int ret;
	enum otr_status_format code;
	ConnContext *ctx = NULL;

	g_return_val_if_fail(server != NULL, TXT_OTR_STB_UNKNOWN);

	ctx = otr_find_context(server, nick, FALSE);
	if (ctx == NULL) {
		code = TXT_OTR_STB_PLAINTEXT;
		return code;
	}

	switch (ctx->msgstate) {
		case OTRL_MSGSTATE_PLAINTEXT:
			code = TXT_OTR_STB_PLAINTEXT;
			break;
		case OTRL_MSGSTATE_ENCRYPTED:
			/* Begin by checking trust. */
			ret = otrl_context_is_fingerprint_trusted(ctx->active_fingerprint);
			if (ret) {
				code = TXT_OTR_STB_TRUST;
			} else {
				code = TXT_OTR_STB_UNTRUSTED;
			}
			break;
		case OTRL_MSGSTATE_FINISHED:
			code = TXT_OTR_STB_FINISHED;
			break;
		default:
			g_warning("BUG! Invalid msgstate: %d", ctx->msgstate);
			code = TXT_OTR_STB_UNKNOWN;
			break;
	}

	if (ctx) {
		IRSSI_OTR_DEBUG("Code: %d, state: %d, sm_prog_state: %d, auth state: %d",
				code, ctx->msgstate, ctx->smstate->sm_prog_state,
				ctx->auth.authstate);
	}
	return code;
}

/*
 * Change status bar text for a given nickname.
 */
void otr_status_change(SERVER_REC *server, const char *nick,
		enum otr_status_event event)
{
	statusbar_items_redraw("otr");
	signal_emit("otr event", 3, server, nick, statusbar_txt[event]);
}

/*
 * Search for a OTR Fingerprint object from the given human readable string and
 * return a pointer to the object if found else NULL.
 */
Fingerprint *otr_find_hash_fingerprint_from_human(const char *human_fp, struct otr_user_state *ustate)
{
	char str_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	Fingerprint *fp = NULL, *fp_iter = NULL;
	ConnContext *context;

	/* Loop on all context of the user state */
	for (context = ustate->otr_state->context_root; context != NULL;
			context = context->next) {
		/* Loop on all fingerprint of the context */
		for (fp_iter = context->fingerprint_root.next; fp_iter;
				fp_iter = fp_iter->next) {
			otrl_privkey_hash_to_human(str_fp, fp_iter->fingerprint);
			/* Compare human fingerprint given in argument to the current. */
			if (strncmp(str_fp, human_fp, sizeof(str_fp)) == 0) {
				fp = otrl_context_find_fingerprint(context,
						fp_iter->fingerprint, 0, NULL);
				return fp;
			}
		}
	}

	return fp;
}

/*
 * Forget a fingerprint.
 *
 * If str_fp is not NULL, it must be on the OTR human format like this:
 * "487FFADA 5073FEDD C5AB5C14 5BB6C1FF 6D40D48A". If str_fp is NULL, get the
 * context of the target nickname, check for the OTR peer context active
 * fingerprint and forget this one if possible.
 */
void otr_forget(SERVER_REC *server, const char *nick, char *str_fp, struct otr_user_state *ustate)
{
	char fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	Fingerprint *fp_forget;
	ConnContext *ctx = NULL;
	struct otr_peer_context *opc;

	/* No human string fingerprint given. */
	if (*str_fp == '\0') {
		ctx = otr_find_context(server, nick, FALSE);
		if (ctx == NULL) {
			return;
		}

		opc = ctx->app_data;
		/* Always NEED a peer context or else code error. */
		g_return_if_fail(opc != NULL);

		fp_forget = opc->active_fingerprint;
	} else {
		fp_forget = otr_find_hash_fingerprint_from_human(str_fp, ustate);
	}

	if (fp_forget) {
		/* Don't do anything if context is in encrypted state. */
		if (check_fp_encrypted_msgstate(fp_forget)) {
			printformat(server, nick, MSGLEVEL_CLIENTCRAP, TXT_OTR_FP_CTX_ENCRYPTED);
			return;
		}

		otrl_privkey_hash_to_human(fp, fp_forget->fingerprint);
		/* Forget fp and context if it's the only one remaining. */
		otrl_context_forget_fingerprint(fp_forget, 1);
		/* Update fingerprints file. */
		key_write_fingerprints(ustate);
		printformat(server, nick, MSGLEVEL_CLIENTCRAP, TXT_OTR_FP_FORGOTTEN, fp);
	} else
		printformat(server, nick, MSGLEVEL_CLIENTERROR, TXT_OTR_FP_MISSING, str_fp);
}

/*
 * Distrust a fingerprint.
 *
 * If str_fp is not NULL, it must be on the OTR human format like this:
 * "487FFADA 5073FEDD C5AB5C14 5BB6C1FF 6D40D48A". If str_fp is NULL, get the
 * context of the target nickname, check for the OTR peer context active
 * fingerprint and distrust it.
 */
void otr_distrust(SERVER_REC *server, const char *nick, char *str_fp,
		struct otr_user_state *ustate)
{
	char fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	Fingerprint *fp_distrust;
	ConnContext *ctx;
	struct otr_peer_context *opc;

	/* No human string fingerprint given. */
	if (*str_fp == '\0') {
		ctx = otr_find_context(server, nick, FALSE);
		if (ctx == NULL) {
			return;
		}

		opc = ctx->app_data;
		/* Always NEED a peer context or else code error. */
		g_return_if_fail(opc != NULL);

		fp_distrust = opc->active_fingerprint;
	} else
		fp_distrust = otr_find_hash_fingerprint_from_human(str_fp, ustate);

	if (fp_distrust != NULL) {
		otrl_privkey_hash_to_human(fp, fp_distrust->fingerprint);

		if (!otrl_context_is_fingerprint_trusted(fp_distrust)) {
			/* Fingerprint already not trusted. Do nothing. */
			printformat(server, nick, MSGLEVEL_CLIENTERROR, TXT_OTR_FP_ALREADY_DISTRUSED, fp);
			return;
		}

		otrl_context_set_trust(fp_distrust, "");

		/* Update fingerprints file. */
		key_write_fingerprints(ustate);
		printformat(server, nick, MSGLEVEL_CLIENTCRAP, TXT_OTR_FP_DISTRUSTED, fp);
	} else
		printformat(server, nick, MSGLEVEL_CLIENTERROR, TXT_OTR_FP_MISSING, str_fp);
}
