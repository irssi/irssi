/*
 * Copyright (c) 2015 Alexander Færøy <ahf@irssi.org>
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

#include "module.h"
#include "signals.h"
#include "settings.h"
#include "levels.h"
#include "tls.h"

#include "module-formats.h"
#include "printtext.h"

#include "fe-tls.h"

static void tls_handshake_finished(SERVER_REC *server, TLS_REC *tls)
{
	if (! settings_get_bool("tls_verbose_connect"))
		return;

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_TLS_CERT_HEADER);

	GSList *certs = NULL;
	for (certs = tls->certs; certs != NULL; certs = certs->next) {
		TLS_CERT_REC *tls_cert_rec = certs->data;

		printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_TLS_CERT_SUBJECT_HEADER);

		GSList *subject = NULL;
		for (subject = tls_cert_rec->subject; subject != NULL; subject = subject->next) {
			TLS_CERT_ENTRY_REC *subject_data = subject->data;
			printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_TLS_CERT_NAMED_ENTRY, subject_data->name, subject_data->value);
		}

		printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_TLS_CERT_ISSUER_HEADER);

		GSList *issuer = NULL;
		for (issuer = tls_cert_rec->issuer; issuer != NULL; issuer = issuer->next) {
			TLS_CERT_ENTRY_REC *issuer_data = issuer->data;
			printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_TLS_CERT_NAMED_ENTRY, issuer_data->name, issuer_data->value);
		}
	}

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_TLS_PROTOCOL_VERSION, tls->protocol_version, tls->cipher_size, tls->cipher);

#ifdef SSL_get_server_tmp_key
	if (tls->ephemeral_key_algorithm != NULL)
		printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_TLS_EPHEMERAL_KEY, tls->ephemeral_key_size, tls->ephemeral_key_algorithm);
	else
		printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_TLS_EPHEMERAL_KEY_UNAVAILBLE);
#endif

	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_TLS_PUBLIC_KEY, tls->public_key_size, tls->public_key_algorithm, tls->not_before, tls->not_after);
	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_TLS_PUBLIC_KEY_FINGERPRINT, tls->public_key_fingerprint, tls->public_key_fingerprint_algorithm);
	printformat(server, NULL, MSGLEVEL_CLIENTNOTICE, TXT_TLS_CERTIFICATE_FINGERPRINT, tls->certificate_fingerprint, tls->certificate_fingerprint_algorithm);
}

void fe_tls_init(void)
{
	settings_add_bool("lookandfeel", "tls_verbose_connect", TRUE);

	signal_add("tls handshake finished", (SIGNAL_FUNC)tls_handshake_finished);
}

void fe_tls_deinit(void)
{
	signal_remove("tls handshake finished", (SIGNAL_FUNC)tls_handshake_finished);
}
