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

#ifndef __TLS_H
#define __TLS_H

#include <openssl/ssl.h>

typedef struct _TLS_REC TLS_REC;
typedef struct _TLS_CERT_REC TLS_CERT_REC;
typedef struct _TLS_CERT_ENTRY_REC TLS_CERT_ENTRY_REC;

struct _TLS_REC {
	char *protocol_version;
	char *cipher;
	size_t cipher_size;

	char *public_key_algorithm;
	char *public_key_fingerprint;
	char *public_key_fingerprint_algorithm;
	size_t public_key_size;

	char *certificate_fingerprint;
	char *certificate_fingerprint_algorithm;

	char *not_after;
	char *not_before;

	char *ephemeral_key_algorithm;
	size_t ephemeral_key_size;

	GSList *certs;
};

struct _TLS_CERT_REC {
	GSList *subject;
	GSList *issuer;
};

struct _TLS_CERT_ENTRY_REC {
	char *name;
	char *value;
};

TLS_REC *tls_create_rec();
void tls_rec_free(TLS_REC *tls_rec);

void tls_rec_set_protocol_version(TLS_REC *tls_rec, const char *protocol_version);
void tls_rec_set_cipher(TLS_REC *tls_rec, const char *cipher);
void tls_rec_set_cipher_size(TLS_REC *tls_rec, size_t size);
void tls_rec_set_public_key_algorithm(TLS_REC *tls_rec, const char *algorithm);
void tls_rec_set_public_key_fingerprint(TLS_REC *tls_rec, const char *fingerprint);
void tls_rec_set_public_key_fingerprint_algorithm(TLS_REC *tls_rec, const char *algorithm);
void tls_rec_set_public_key_size(TLS_REC *tls_rec, size_t size);
void tls_rec_set_certificate_fingerprint(TLS_REC *tls_rec, const char *fingerprint);
void tls_rec_set_certificate_fingerprint_algorithm(TLS_REC *tls_rec, const char *algorithm);
void tls_rec_set_not_after(TLS_REC *tls_rec, const char *not_after);
void tls_rec_set_not_before(TLS_REC *tls_rec, const char *not_before);
void tls_rec_set_ephemeral_key_algorithm(TLS_REC *tls_rec, const char *algorithm);
void tls_rec_set_ephemeral_key_size(TLS_REC *tls_rec, size_t size);

void tls_rec_append_cert(TLS_REC *tls_rec, TLS_CERT_REC *tls_cert_rec);

TLS_CERT_REC *tls_cert_create_rec();
void tls_cert_rec_free(TLS_CERT_REC *tls_cert_rec);

void tls_cert_rec_append_subject_entry(TLS_CERT_REC *tls_cert_rec, TLS_CERT_ENTRY_REC *tls_cert_entry_rec);
void tls_cert_rec_append_issuer_entry(TLS_CERT_REC *tls_cert_rec, TLS_CERT_ENTRY_REC *tls_cert_entry_rec);

TLS_CERT_ENTRY_REC *tls_cert_entry_create_rec(const char *name, const char *value);
void tls_cert_entry_rec_free(TLS_CERT_ENTRY_REC *tls_cert_entry);

#endif
