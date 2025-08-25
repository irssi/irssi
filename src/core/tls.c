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

#include <irssi/src/core/tls.h>

TLS_REC *tls_create_rec()
{
	TLS_REC *rec = g_new0(TLS_REC, 1);
	g_return_val_if_fail(rec != NULL, NULL);

	return rec;
}

void tls_rec_free(TLS_REC *tls_rec)
{
	if (tls_rec == NULL)
		return;

	g_free_and_null(tls_rec->protocol_version);
	g_free_and_null(tls_rec->cipher);
	g_free_and_null(tls_rec->public_key_algorithm);
	g_free_and_null(tls_rec->public_key_fingerprint);
	g_free_and_null(tls_rec->public_key_fingerprint_algorithm);
	g_free_and_null(tls_rec->certificate_fingerprint);
	g_free_and_null(tls_rec->certificate_fingerprint_algorithm);
	g_free_and_null(tls_rec->not_after);
	g_free_and_null(tls_rec->not_before);
	g_free_and_null(tls_rec->ephemeral_key_algorithm);

	if (tls_rec->certs != NULL) {
		g_slist_foreach(tls_rec->certs, (GFunc)tls_cert_rec_free, NULL);
		g_slist_free(tls_rec->certs);
		tls_rec->certs = NULL;
	}

	g_free(tls_rec);
}

void tls_rec_set_protocol_version(TLS_REC *tls_rec, const char *protocol_version)
{
	g_return_if_fail(tls_rec != NULL);

	tls_rec->protocol_version = g_strdup(protocol_version);
}

void tls_rec_set_cipher(TLS_REC *tls_rec, const char *cipher)
{
	g_return_if_fail(tls_rec != NULL);

	tls_rec->cipher = g_strdup(cipher);
}

void tls_rec_set_cipher_size(TLS_REC *tls_rec, size_t size)
{
	g_return_if_fail(tls_rec != NULL);

	tls_rec->cipher_size = size;
}

void tls_rec_set_public_key_algorithm(TLS_REC *tls_rec, const char *algorithm)
{
	g_return_if_fail(tls_rec != NULL);

	tls_rec->public_key_algorithm = g_strdup(algorithm);
}

void tls_rec_set_public_key_fingerprint(TLS_REC *tls_rec, const char *fingerprint)
{
	g_return_if_fail(tls_rec != NULL);

	tls_rec->public_key_fingerprint = g_strdup(fingerprint);
}

void tls_rec_set_public_key_fingerprint_algorithm(TLS_REC *tls_rec, const char *algorithm)
{
	g_return_if_fail(tls_rec != NULL);

	tls_rec->public_key_fingerprint_algorithm = g_strdup(algorithm);
}

void tls_rec_set_public_key_size(TLS_REC *tls_rec, size_t size)
{
	g_return_if_fail(tls_rec != NULL);
	tls_rec->public_key_size = size;
}

void tls_rec_set_certificate_fingerprint(TLS_REC *tls_rec, const char *fingerprint)
{
	g_return_if_fail(tls_rec != NULL);

	tls_rec->certificate_fingerprint = g_strdup(fingerprint);
}

void tls_rec_set_certificate_fingerprint_algorithm(TLS_REC *tls_rec, const char *algorithm)
{
	g_return_if_fail(tls_rec != NULL);

	tls_rec->certificate_fingerprint_algorithm = g_strdup(algorithm);
}

void tls_rec_set_not_after(TLS_REC *tls_rec, const char *not_after)
{
	g_return_if_fail(tls_rec != NULL);
	tls_rec->not_after = g_strdup(not_after);
}

void tls_rec_set_not_before(TLS_REC *tls_rec, const char *not_before)
{
	g_return_if_fail(tls_rec != NULL);
	tls_rec->not_before = g_strdup(not_before);
}

void tls_rec_set_ephemeral_key_algorithm(TLS_REC *tls_rec, const char *algorithm)
{
	g_return_if_fail(tls_rec != NULL);
	tls_rec->ephemeral_key_algorithm = g_strdup(algorithm);
}

void tls_rec_set_ephemeral_key_size(TLS_REC *tls_rec, size_t size)
{
	g_return_if_fail(tls_rec != NULL);
	tls_rec->ephemeral_key_size = size;
}

void tls_rec_append_cert(TLS_REC *tls_rec, TLS_CERT_REC *tls_cert_rec)
{
	g_return_if_fail(tls_rec != NULL);
	g_return_if_fail(tls_cert_rec != NULL);

	tls_rec->certs = g_slist_append(tls_rec->certs, tls_cert_rec);
}

TLS_CERT_REC *tls_cert_create_rec()
{
	TLS_CERT_REC *rec = g_new0(TLS_CERT_REC, 1);
	g_return_val_if_fail(rec != NULL, NULL);

	return rec;
}

void tls_cert_rec_append_subject_entry(TLS_CERT_REC *tls_cert_rec, TLS_CERT_ENTRY_REC *tls_cert_entry_rec)
{
	g_return_if_fail(tls_cert_rec != NULL);
	g_return_if_fail(tls_cert_entry_rec != NULL);

	tls_cert_rec->subject = g_slist_append(tls_cert_rec->subject, tls_cert_entry_rec);
}

void tls_cert_rec_append_issuer_entry(TLS_CERT_REC *tls_cert_rec, TLS_CERT_ENTRY_REC *tls_cert_entry_rec)
{
	g_return_if_fail(tls_cert_rec != NULL);
	g_return_if_fail(tls_cert_entry_rec != NULL);

	tls_cert_rec->issuer = g_slist_append(tls_cert_rec->issuer, tls_cert_entry_rec);
}

void tls_cert_rec_free(TLS_CERT_REC *tls_cert_rec)
{
	if (tls_cert_rec == NULL)
		return;

	if (tls_cert_rec->subject != NULL) {
		g_slist_foreach(tls_cert_rec->subject, (GFunc)tls_cert_entry_rec_free, NULL);
		g_slist_free(tls_cert_rec->subject);
		tls_cert_rec->subject = NULL;
	}

	if (tls_cert_rec->issuer != NULL) {
		g_slist_foreach(tls_cert_rec->issuer, (GFunc)tls_cert_entry_rec_free, NULL);
		g_slist_free(tls_cert_rec->issuer);
		tls_cert_rec->issuer = NULL;
	}

	g_free(tls_cert_rec);
}

TLS_CERT_ENTRY_REC *tls_cert_entry_create_rec(const char *name, const char *value)
{
	TLS_CERT_ENTRY_REC *rec = g_new0(TLS_CERT_ENTRY_REC, 1);
	g_return_val_if_fail(rec != NULL, NULL);

	rec->name  = g_strdup(name);
	rec->value = g_strdup(value);

	return rec;
}

void tls_cert_entry_rec_free(TLS_CERT_ENTRY_REC *tls_cert_entry)
{
	if (tls_cert_entry == NULL)
		return;

	g_free_and_null(tls_cert_entry->name);
	g_free_and_null(tls_cert_entry->value);

	g_free(tls_cert_entry);
}
