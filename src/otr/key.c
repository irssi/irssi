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
#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <signal.h>
#include <unistd.h>

#include "key.h"

#include "levels.h"
#include "network.h"
#include "pidwait.h"
#include "printtext.h"

#include "irssi-otr.h"
#include "otr-formats.h"

/*
 * Status of key generation.
 */
enum key_gen_status {
	KEY_GEN_IDLE		= 0,
	KEY_GEN_RUNNING		= 1,
	KEY_GEN_FINISHED	= 2,
	KEY_GEN_ERROR		= 3,
};

/*
 * Data of the state of key generation.
 */
struct key_gen_data {
	struct otr_user_state *ustate;
	char *account_name;
	char *key_file_path;
	enum key_gen_status status;
	gcry_error_t gcry_error;
};

/*
 * Event from the key generation process.
 */
struct key_gen_event {
	enum key_gen_status status;
	gcry_error_t error;
};

/*
 * Key generation process.
 */
struct key_gen_worker {
	int tag;
	GIOChannel *pipes[2];
};

/*
 * Key generation data for the thread in charge of creating the key.
 */
static struct key_gen_data key_gen_state = {
	.status = KEY_GEN_IDLE,
	.gcry_error = GPG_ERR_NO_ERROR,
};

/*
 * Build file path concatenate to the irssi config dir.
 */
static char *file_path_build(const char *path)
{
	g_assert(path != NULL);

	int ret;
	char *filename;

	/* Either NULL or the filename is returned here which is valid. */
	ret = asprintf(&filename, "%s/%s", get_irssi_dir(), path);
	if (ret < 0) {
		filename = NULL;
	}

	return filename;
}

/*
 * Emit a key generation status event.
 */
static void emit_event(GIOChannel *pipe, enum key_gen_status status, gcry_error_t error)
{
	struct key_gen_event event;

	g_assert(pipe != NULL);

	event.status = status;
	event.error = error;

	g_io_channel_write_block(pipe, &event, sizeof(event));
}

/*
 * Reset key generation state and status is IDLE.
 */
static void reset_key_gen_state(void)
{
	/* Safety. */
	if (key_gen_state.key_file_path != NULL) {
		free(key_gen_state.key_file_path);
	}

	/* Pointer dup when key_gen_run is called. */
	if (key_gen_state.account_name != NULL) {
		free(key_gen_state.account_name);
	}

	/* Nullify everything. */
	memset(&key_gen_state, 0, sizeof(key_gen_state));
	key_gen_state.status = KEY_GEN_IDLE;
	key_gen_state.gcry_error = GPG_ERR_NO_ERROR;
}

/*
 * Read status event from key generation worker.
 */
static void read_key_gen_status(struct key_gen_worker *worker, GIOChannel *pipe)
{
	struct key_gen_event event;
	gcry_error_t err;

	g_assert(worker != NULL);

	fcntl(g_io_channel_unix_get_fd(pipe), F_SETFL, O_NONBLOCK);

	if (g_io_channel_read_block(pipe, &event, sizeof(event)) == -1) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
				TXT_OTR_KEYGEN_FAILED,
				key_gen_state.account_name,
				g_strerror(errno));
		return;
	}

	key_gen_state.status = event.status;
	key_gen_state.gcry_error = event.error;

	if (event.status == KEY_GEN_FINISHED || event.status == KEY_GEN_ERROR) {
		/* Worker is done. */
		g_source_remove(worker->tag);

		g_io_channel_shutdown(worker->pipes[0], TRUE, NULL);
		g_io_channel_unref(worker->pipes[0]);

		g_io_channel_shutdown(worker->pipes[1], TRUE, NULL);
		g_io_channel_unref(worker->pipes[1]);

		g_free(worker);

		if (event.status == KEY_GEN_ERROR) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
					TXT_OTR_KEYGEN_FAILED,
					key_gen_state.account_name,
					gcry_strerror(key_gen_state.gcry_error));
			reset_key_gen_state();
			return;
		}

		err = otrl_privkey_read(key_gen_state.ustate->otr_state, key_gen_state.key_file_path);

		if (err != GPG_ERR_NO_ERROR) {
			printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
					TXT_OTR_KEYGEN_FAILED,
					key_gen_state.account_name,
					gcry_strerror(key_gen_state.gcry_error));
		} else {
			printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE,
					TXT_OTR_KEYGEN_COMPLETED,
					key_gen_state.account_name);
		}

		reset_key_gen_state();
	}
}

/*
 * Run key generation in a seperate process (takes ages). The other process
 * will rewrite the key file, we shouldn't change anything till it's done and
 * we've reloaded the keys.
 */
void key_gen_run(struct otr_user_state *ustate, const char *account_name)
{
	struct key_gen_worker *worker;
	int fd[2];

	g_assert(ustate != NULL);
	g_assert(account_name != NULL);

	if (key_gen_state.status != KEY_GEN_IDLE) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_OTR_KEYGEN_RUNNING, key_gen_state.account_name);
		return;
	}

	/* Make sure the pointer does not go away during the proess. */
	key_gen_state.account_name = strdup(account_name);
	key_gen_state.ustate = ustate;

	/* Creating key file path. */
	key_gen_state.key_file_path = file_path_build(OTR_KEYFILE);
	if (key_gen_state.key_file_path == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
				TXT_OTR_KEYGEN_FAILED,
				key_gen_state.account_name,
				g_strerror(errno));
		reset_key_gen_state();
		return;
	}

	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, TXT_OTR_KEYGEN_STARTED, key_gen_state.account_name);

	if (pipe(fd) != 0) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
				TXT_OTR_KEYGEN_FAILED,
				key_gen_state.account_name,
				g_strerror(errno));
		reset_key_gen_state();
		return;
	}

	worker = g_new0(struct key_gen_worker, 1);

	if (worker == NULL) {
		printformat(NULL, NULL, MSGLEVEL_CLIENTERROR,
				TXT_OTR_KEYGEN_FAILED,
				key_gen_state.account_name,
				g_strerror(errno));
		reset_key_gen_state();
		return;
	}

	worker->pipes[0] = g_io_channel_new(fd[0]);
	worker->pipes[1] = g_io_channel_new(fd[1]);

	pid_t pid;
	pid = fork();

	if (pid > 0) {
		/* Parent process */
		pidwait_add(pid);
		worker->tag = g_input_add(worker->pipes[0], G_INPUT_READ, (GInputFunction)read_key_gen_status, worker);
		return;
	}

	if (pid != 0) {
		/* error */
		g_warning("Key generation failed: %s", g_strerror(errno));

		g_source_remove(worker->tag);

		g_io_channel_shutdown(worker->pipes[0], TRUE, NULL);
		g_io_channel_unref(worker->pipes[0]);

		g_io_channel_shutdown(worker->pipes[1], TRUE, NULL);
		g_io_channel_unref(worker->pipes[1]);

		g_free(worker);

		return;
	}

	/* Child process */
	gcry_error_t err;

	key_gen_state.status = KEY_GEN_RUNNING;
	emit_event(worker->pipes[1], KEY_GEN_RUNNING, GPG_ERR_NO_ERROR);

	err = otrl_privkey_generate(key_gen_state.ustate->otr_state, key_gen_state.key_file_path, key_gen_state.account_name, OTR_PROTOCOL_ID);

	if (err != GPG_ERR_NO_ERROR) {
		emit_event(worker->pipes[1], KEY_GEN_ERROR, err);
		_exit(99);
		return;
	}

	emit_event(worker->pipes[1], KEY_GEN_FINISHED, GPG_ERR_NO_ERROR);

	_exit(99);
}

/*
 * Write fingerprints to file.
 */
void key_write_fingerprints(struct otr_user_state *ustate)
{
	gcry_error_t err;
	char *filename;

	g_assert(ustate != NULL);

	filename = file_path_build(OTR_FINGERPRINTS_FILE);
	if (filename == NULL) {
		return;
	}

	err = otrl_privkey_write_fingerprints(ustate->otr_state, filename);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_OTR_DEBUG("Fingerprints saved to %9%s%9", filename);
	} else {
		IRSSI_OTR_DEBUG("Error writing fingerprints: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}

	free(filename);
}

/*
 * Write instance tags to file.
 */
void key_write_instags(struct otr_user_state *ustate)
{
	gcry_error_t err;
	char *filename;

	g_assert(ustate != NULL);

	filename = file_path_build(OTR_INSTAG_FILE);
	if (filename == NULL) {
		return;
	}

	err = otrl_instag_write(ustate->otr_state, filename);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_OTR_DEBUG("Instance tags saved in %9%s%9", filename);
	} else {
		IRSSI_OTR_DEBUG("Error saving instance tags: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}

	free(filename);
}

/*
 * Load private keys.
 */
void key_load(struct otr_user_state *ustate)
{
	int ret;
	gcry_error_t err;
	char *filename;

	g_assert(ustate != NULL);

	filename = file_path_build(OTR_KEYFILE);
	if (filename == NULL) {
		return;
	}

	ret = access(filename, F_OK);
	if (ret < 0) {
		IRSSI_OTR_DEBUG("No private keys found in %9%s%9", filename);
		free(filename);
		return;
	}

	err = otrl_privkey_read(ustate->otr_state, filename);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_OTR_DEBUG("Private keys loaded from %9%s%9", filename);
	} else {
		IRSSI_OTR_DEBUG("Error loading private keys: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}
}

/*
 * Load fingerprints.
 */
void key_load_fingerprints(struct otr_user_state *ustate)
{
	int ret;
	gcry_error_t err;
	char *filename;

	g_assert(ustate != NULL);

	filename = file_path_build(OTR_FINGERPRINTS_FILE);
	if (filename == NULL) {
		return;
	}

	ret = access(filename, F_OK);
	if (ret < 0) {
		IRSSI_OTR_DEBUG("No fingerprints found in %9%s%9", filename);
		free(filename);
		return;
	}

	err = otrl_privkey_read_fingerprints(ustate->otr_state, filename, NULL,
			NULL);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_OTR_DEBUG("Fingerprints loaded from %9%s%9", filename);
	} else {
		IRSSI_OTR_DEBUG("Error loading fingerprints: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}
}
