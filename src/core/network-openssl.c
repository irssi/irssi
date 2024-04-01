/*
 network-ssl.c : SSL support

    Copyright (C) 2002 vjt

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "module.h"
#include <irssi/src/core/network.h>
#include <irssi/src/core/network-openssl.h>
#include <irssi/src/core/net-sendbuffer.h>
#include <irssi/src/core/misc.h>
#include <irssi/src/core/servers.h>
#include <irssi/src/core/signals.h>
#include <irssi/src/core/tls.h>

#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* OpenSSL 1.1.0 introduced some backward-incompatible changes to the api */
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && \
    (!defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x2070000fL)
/* The two functions below could be already defined if OPENSSL_API_COMPAT is
 * below the 1.1.0 version so let's do a clean start */
#undef  X509_get_notBefore
#undef  X509_get_notAfter
#define X509_get_notBefore(x)     X509_get0_notBefore(x)
#define X509_get_notAfter(x)      X509_get0_notAfter(x)
#define ASN1_STRING_data(x)       ASN1_STRING_get0_data(x)
#endif

/* OpenSSL 1.1.0 also introduced some useful additions to the api */
#if (OPENSSL_VERSION_NUMBER >= 0x10002000L)
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined (LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)
static int X509_STORE_up_ref(X509_STORE *vfy)
{
    int n;

    n = CRYPTO_add(&vfy->references, 1, CRYPTO_LOCK_X509_STORE);
    g_assert(n > 1);

    return (n > 1) ? 1 : 0;
}
#endif
#endif

/* ssl i/o channel object */
typedef struct
{
	GIOChannel pad;
	gint fd;
	GIOChannel *giochan;
	SSL *ssl;
	SSL_CTX *ctx;
	unsigned int verify:1;
	SERVER_REC *server;
	int port;
} GIOSSLChannel;

static int ssl_inited = FALSE;
/* https://github.com/irssi/irssi/issues/820 */
#if (OPENSSL_VERSION_NUMBER >= 0x10002000L)
static X509_STORE *store = NULL;
#endif

static void irssi_ssl_free(GIOChannel *handle)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	g_io_channel_unref(chan->giochan);
	SSL_free(chan->ssl);
	SSL_CTX_free(chan->ctx);
	g_free(chan);
}

/* Checks if the given string has internal NUL characters. */
static gboolean has_internal_nul(const char* str, int len) {
	/* Remove trailing nul characters. They would give false alarms */
	while (len > 0 && str[len-1] == 0)
		len--;
	return strlen(str) != len;
}

/* tls_dns_name - Extract valid DNS name from subjectAltName value */
static const char *tls_dns_name(const GENERAL_NAME * gn)
{
	const char *dnsname;

	/* We expect the OpenSSL library to construct GEN_DNS extension objects as
	   ASN1_IA5STRING values. Check we got the right union member. */
	if (ASN1_STRING_type(gn->d.ia5) != V_ASN1_IA5STRING) {
		g_warning("Invalid ASN1 value type in subjectAltName");
		return NULL;
	}

	/* Safe to treat as an ASCII string possibly holding a DNS name */
	dnsname = (char *) ASN1_STRING_data(gn->d.ia5);

	if (has_internal_nul(dnsname, ASN1_STRING_length(gn->d.ia5))) {
		g_warning("Internal NUL in subjectAltName");
		return NULL;
	}

	return dnsname;
}

/* tls_text_name - extract certificate property value by name */
static char *tls_text_name(X509_NAME *name, int nid)
{
	int     pos;
	X509_NAME_ENTRY *entry;
	ASN1_STRING *entry_str;
	int     utf8_length;
	unsigned char *utf8_value;
	char *result;

	if (name == 0 || (pos = X509_NAME_get_index_by_NID(name, nid, -1)) < 0) {
		return NULL;
	}

	entry = X509_NAME_get_entry(name, pos);
	g_return_val_if_fail(entry != NULL, NULL);
	entry_str = X509_NAME_ENTRY_get_data(entry);
	g_return_val_if_fail(entry_str != NULL, NULL);

	/* Convert everything into UTF-8. It's up to OpenSSL to do something
	   reasonable when converting ASCII formats that contain non-ASCII
	   content. */
	if ((utf8_length = ASN1_STRING_to_UTF8(&utf8_value, entry_str)) < 0) {
		g_warning("Error decoding ASN.1 type=%d", ASN1_STRING_type(entry_str));
		return NULL;
	}

	if (has_internal_nul((char *)utf8_value, utf8_length)) {
		g_warning("NUL character in hostname in certificate");
		OPENSSL_free(utf8_value);
		return NULL;
	}

	result = g_strdup((char *) utf8_value);
	OPENSSL_free(utf8_value);
	return result;
}


/** check if a hostname in the certificate matches the hostname we used for the connection */
static gboolean match_hostname(const char *cert_hostname, const char *hostname)
{
	const char *hostname_left;

	if (!strcasecmp(cert_hostname, hostname)) { /* exact match */
		return TRUE;
	} else if (cert_hostname[0] == '*' && cert_hostname[1] == '.' && cert_hostname[2] != 0) { /* wildcard match */
		/* The initial '*' matches exactly one hostname component */
		hostname_left = strchr(hostname, '.');
		if (hostname_left != NULL && ! strcasecmp(hostname_left + 1, cert_hostname + 2)) {
			return TRUE;
		}
	}
	return FALSE;
}

/* based on verify_extract_name from tls_client.c in postfix */
static gboolean irssi_ssl_verify_hostname(X509 *cert, const char *hostname)
{
	int gen_index, gen_count;
	gboolean matched = FALSE, has_dns_name = FALSE;
	const char *cert_dns_name;
	char *cert_subject_cn;
	const GENERAL_NAME *gn;
	STACK_OF(GENERAL_NAME) * gens;

	/* Verify the dNSName(s) in the peer certificate against the hostname. */
	gens = X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0);
	if (gens) {
		gen_count = sk_GENERAL_NAME_num(gens);
		for (gen_index = 0; gen_index < gen_count && !matched; ++gen_index) {
			gn = sk_GENERAL_NAME_value(gens, gen_index);
			if (gn->type != GEN_DNS)
				continue;

			/* Even if we have an invalid DNS name, we still ultimately
			   ignore the CommonName, because subjectAltName:DNS is
			   present (though malformed). */
			has_dns_name = TRUE;
			cert_dns_name = tls_dns_name(gn);
			if (cert_dns_name && *cert_dns_name) {
				matched = match_hostname(cert_dns_name, hostname);
			}
		}

		/* Free stack *and* member GENERAL_NAME objects */
		sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	}

	if (has_dns_name) {
		if (! matched) {
			/* The CommonName in the issuer DN is obsolete when SubjectAltName is available. */
			g_warning("None of the Subject Alt Names in the certificate match hostname '%s'", hostname);
		}
		return matched;
	} else { /* No subjectAltNames, look at CommonName */
		cert_subject_cn = tls_text_name(X509_get_subject_name(cert), NID_commonName);
		if (cert_subject_cn && *cert_subject_cn) {
			matched = match_hostname(cert_subject_cn, hostname);
			if (! matched) {
				g_warning("SSL certificate common name '%s' doesn't match host name '%s'", cert_subject_cn, hostname);
			}
		} else {
			g_warning("No subjectAltNames and no valid common name in certificate");
		}
		g_free(cert_subject_cn);
	}

	return matched;
}

static gboolean irssi_ssl_verify(SSL *ssl, SSL_CTX *ctx, const char* hostname, int port, X509 *cert, SERVER_REC *server, TLS_REC *tls_rec)
{
	long result;

	result = SSL_get_verify_result(ssl);
	if (result != X509_V_OK) {
		g_warning("Could not verify TLS servers certificate: %s", X509_verify_cert_error_string(result));
		return FALSE;
	} else if (! irssi_ssl_verify_hostname(cert, hostname)){
		return FALSE;
	}
	return TRUE;
}

static GIOStatus irssi_ssl_read(GIOChannel *handle, gchar *buf, gsize len, gsize *ret, GError **gerr)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	gint ret1, err;
	const char *errstr;
	gchar *errmsg;

	ERR_clear_error();
	ret1 = SSL_read(chan->ssl, buf, len);
	if(ret1 <= 0)
	{
		*ret = 0;
		err = SSL_get_error(chan->ssl, ret1);
		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return G_IO_STATUS_AGAIN;
		else if(err == SSL_ERROR_ZERO_RETURN)
			return G_IO_STATUS_EOF;
		else if (err == SSL_ERROR_SYSCALL)
		{
			errstr = ERR_reason_error_string(ERR_get_error());
			if (errstr == NULL && ret1 == -1)
				errstr = strerror(errno);
			if (errstr == NULL)
				errstr = "server closed connection unexpectedly";
		}
		else
		{
			errstr = ERR_reason_error_string(ERR_get_error());
			if (errstr == NULL)
				errstr = "unknown SSL error";
		}
		errmsg = g_strdup_printf("SSL read error: %s", errstr);
		*gerr = g_error_new_literal(G_IO_CHANNEL_ERROR, G_IO_CHANNEL_ERROR_FAILED,
					    errmsg);
		g_free(errmsg);
		return G_IO_STATUS_ERROR;
	}
	else
	{
		*ret = ret1;
		return G_IO_STATUS_NORMAL;
	}
	/*UNREACH*/
	return G_IO_STATUS_ERROR;
}

static GIOStatus irssi_ssl_write(GIOChannel *handle, const gchar *buf, gsize len, gsize *ret, GError **gerr)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	gint ret1, err;
	const char *errstr;
	gchar *errmsg;

	ERR_clear_error();
	ret1 = SSL_write(chan->ssl, (const char *)buf, len);
	if(ret1 <= 0)
	{
		*ret = 0;
		err = SSL_get_error(chan->ssl, ret1);
		if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
			return G_IO_STATUS_AGAIN;
		else if(err == SSL_ERROR_ZERO_RETURN)
			errstr = "server closed connection";
		else if (err == SSL_ERROR_SYSCALL)
		{
			errstr = ERR_reason_error_string(ERR_get_error());
			if (errstr == NULL && ret1 == -1)
				errstr = strerror(errno);
			if (errstr == NULL)
				errstr = "server closed connection unexpectedly";
		}
		else
		{
			errstr = ERR_reason_error_string(ERR_get_error());
			if (errstr == NULL)
				errstr = "unknown SSL error";
		}
		errmsg = g_strdup_printf("SSL write error: %s", errstr);
		*gerr = g_error_new_literal(G_IO_CHANNEL_ERROR, G_IO_CHANNEL_ERROR_FAILED,
					    errmsg);
		g_free(errmsg);
		return G_IO_STATUS_ERROR;
	}
	else
	{
		*ret = ret1;
		return G_IO_STATUS_NORMAL;
	}
	/*UNREACH*/
	return G_IO_STATUS_ERROR;
}

static GIOStatus irssi_ssl_seek(GIOChannel *handle, gint64 offset, GSeekType type, GError **gerr)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;

	return chan->giochan->funcs->io_seek(handle, offset, type, gerr);
}

static GIOStatus irssi_ssl_close(GIOChannel *handle, GError **gerr)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;

	return chan->giochan->funcs->io_close(handle, gerr);
}

static GSource *irssi_ssl_create_watch(GIOChannel *handle, GIOCondition cond)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;

	return chan->giochan->funcs->io_create_watch(handle, cond);
}

static GIOStatus irssi_ssl_set_flags(GIOChannel *handle, GIOFlags flags, GError **gerr)
{
    GIOSSLChannel *chan = (GIOSSLChannel *)handle;

    return chan->giochan->funcs->io_set_flags(handle, flags, gerr);
}

static GIOFlags irssi_ssl_get_flags(GIOChannel *handle)
{
    GIOSSLChannel *chan = (GIOSSLChannel *)handle;

    return chan->giochan->funcs->io_get_flags(handle);
}

static GIOFuncs irssi_ssl_channel_funcs = {
    irssi_ssl_read,
    irssi_ssl_write,
    irssi_ssl_seek,
    irssi_ssl_close,
    irssi_ssl_create_watch,
    irssi_ssl_free,
    irssi_ssl_set_flags,
    irssi_ssl_get_flags
};

gboolean irssi_ssl_init(void)
{
#if (OPENSSL_VERSION_NUMBER >= 0x10002000L)
	int success;
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	if (!OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, NULL)) {
		g_error("Could not initialize OpenSSL");
		return FALSE;
	}
#else
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10002000L)
	store = X509_STORE_new();
	if (store == NULL) {
		g_error("Could not initialize OpenSSL: X509_STORE_new() failed");
		return FALSE;
	}

	success = X509_STORE_set_default_paths(store);
	if (success == 0) {
		g_warning("Could not load default certificates");
		X509_STORE_free(store);
		store = NULL;
		/* Don't return an error; the user might have their own cafile/capath. */
	}
#endif

	ssl_inited = TRUE;

	return TRUE;
}

static int get_pem_password_callback(char *buffer, int max_length, int rwflag, void *pass)
{
	char *password;
	size_t length;

	if (pass == NULL)
		return 0;

	password = (char *)pass;
	length = strlen(pass);

	if (length > max_length)
		return 0;

	memcpy(buffer, password, length + 1);
	return length;
}

static GIOChannel *irssi_ssl_get_iochannel(GIOChannel *handle, int port, SERVER_REC *server)
{
	GIOSSLChannel *chan;
	GIOChannel *gchan;
	int fd;
	SSL *ssl;
	SSL_CTX *ctx = NULL;

	const char *mycert = server->connrec->tls_cert;
	const char *mypkey = server->connrec->tls_pkey;
	const char *mypass = server->connrec->tls_pass;
	const char *cafile = server->connrec->tls_cafile;
	const char *capath = server->connrec->tls_capath;
	const char *ciphers = server->connrec->tls_ciphers;
	gboolean verify = server->connrec->tls_verify;

	g_return_val_if_fail(handle != NULL, NULL);

	if(!ssl_inited && !irssi_ssl_init())
		return NULL;

	if(!(fd = g_io_channel_unix_get_fd(handle)))
		return NULL;

	ERR_clear_error();
	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL) {
		g_error("Could not allocate memory for SSL context");
		return NULL;
	}
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	SSL_CTX_set_default_passwd_cb(ctx, get_pem_password_callback);
	SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)mypass);

	if (ciphers != NULL && ciphers[0] != '\0') {
		if (SSL_CTX_set_cipher_list(ctx, ciphers) != 1)
			g_warning("No valid SSL cipher suite could be selected");
	}

	if (mycert && *mycert) {
		char *scert = NULL, *spkey = NULL;
		FILE *fp;
		scert = convert_home(mycert);
		if (mypkey && *mypkey)
			spkey = convert_home(mypkey);

		if ((fp = fopen(scert, "r"))) {
			X509 *cert;
			/* Let's parse the certificate by hand instead of using
			 * SSL_CTX_use_certificate_file so that we can validate
			 * some parts of it. */
			cert = PEM_read_X509(fp, NULL, get_pem_password_callback, (void *)mypass);
			if (cert != NULL) {
				/* Only the expiration date is checked right now */
				if (X509_cmp_current_time(X509_get_notAfter(cert))  <= 0 ||
				    X509_cmp_current_time(X509_get_notBefore(cert)) >= 0)
					g_warning("The client certificate is expired");

				ERR_clear_error();
				if (! SSL_CTX_use_certificate(ctx, cert))
					g_warning("Loading of client certificate '%s' failed: %s", mycert, ERR_reason_error_string(ERR_get_error()));
				else if (! SSL_CTX_use_PrivateKey_file(ctx, spkey ? spkey : scert, SSL_FILETYPE_PEM))
					g_warning("Loading of private key '%s' failed: %s", mypkey ? mypkey : mycert, ERR_reason_error_string(ERR_get_error()));
				else if (! SSL_CTX_check_private_key(ctx))
					g_warning("Private key does not match the certificate");

				X509_free(cert);
			} else
				g_warning("Loading of client certificate '%s' failed: %s", mycert, ERR_reason_error_string(ERR_get_error()));

			fclose(fp);
		} else
			g_warning("Could not find client certificate '%s'", scert);
		g_free(scert);
		g_free(spkey);
	}

	if ((cafile && *cafile) || (capath && *capath)) {
		char *scafile = NULL;
		char *scapath = NULL;
		if (cafile && *cafile)
			scafile = convert_home(cafile);
		if (capath && *capath)
			scapath = convert_home(capath);
		if (! SSL_CTX_load_verify_locations(ctx, scafile, scapath)) {
			g_warning("Could not load CA list for verifying TLS server certificate");
			g_free(scafile);
			g_free(scapath);
			SSL_CTX_free(ctx);
			return NULL;
		}
		g_free(scafile);
		g_free(scapath);
		verify = TRUE;
	}
#if (OPENSSL_VERSION_NUMBER >= 0x10002000L)
	  else if (store != NULL) {
		/* Make sure to increment the refcount every time the store is
		 * used, that's essential not to get it free'd by OpenSSL when
		 * the SSL_CTX is destroyed. */
		X509_STORE_up_ref(store);
		SSL_CTX_set_cert_store(ctx, store);
	}
#else
	  else {
		if (!SSL_CTX_set_default_verify_paths(ctx))
			g_warning("Could not load default certificates");
	}
#endif

	if(!(ssl = SSL_new(ctx)))
	{
		g_warning("Failed to allocate SSL structure");
		SSL_CTX_free(ctx);
		return NULL;
	}

	if(!SSL_set_fd(ssl, fd))
	{
		g_warning("Failed to associate socket to SSL stream");
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		return NULL;
	}

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	SSL_set_tlsext_host_name(ssl, server->connrec->address);
#endif

	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE |
			SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	chan = g_new0(GIOSSLChannel, 1);
	chan->fd = fd;
	chan->giochan = handle;
	chan->ssl = ssl;
	chan->ctx = ctx;
	chan->server = server;
	chan->port = port;
	chan->verify = verify;

	gchan = (GIOChannel *)chan;
	gchan->funcs = &irssi_ssl_channel_funcs;
	g_io_channel_init(gchan);
	gchan->is_readable = gchan->is_writeable = TRUE;
	gchan->use_buffer = FALSE;

	return gchan;
}

static void set_cipher_info(TLS_REC *tls, SSL *ssl)
{
	g_return_if_fail(tls != NULL);
	g_return_if_fail(ssl != NULL);

	tls_rec_set_protocol_version(tls, SSL_get_version(ssl));

	tls_rec_set_cipher(tls, SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
	tls_rec_set_cipher_size(tls, SSL_get_cipher_bits(ssl, NULL));
}

static gboolean set_pubkey_info(TLS_REC *tls, X509 *cert, unsigned char *cert_fingerprint, size_t cert_fingerprint_size, unsigned char *public_key_fingerprint, size_t public_key_fingerprint_size)
{
	gboolean ret = TRUE;
	EVP_PKEY *pubkey = NULL;
	char *cert_fingerprint_hex = NULL;
	char *public_key_fingerprint_hex = NULL;

	BIO *bio = NULL;
	char buffer[128];
	ssize_t length;

	g_return_val_if_fail(tls != NULL, FALSE);
	g_return_val_if_fail(cert != NULL, FALSE);

	pubkey = X509_get_pubkey(cert);

	cert_fingerprint_hex = binary_to_hex(cert_fingerprint, cert_fingerprint_size);
	tls_rec_set_certificate_fingerprint(tls, cert_fingerprint_hex);
	tls_rec_set_certificate_fingerprint_algorithm(tls, "SHA256");

	/* Show algorithm. */
	switch (EVP_PKEY_id(pubkey)) {
		case EVP_PKEY_RSA:
			tls_rec_set_public_key_algorithm(tls, "RSA");
			break;

		case EVP_PKEY_DSA:
			tls_rec_set_public_key_algorithm(tls, "DSA");
			break;

		case EVP_PKEY_EC:
			tls_rec_set_public_key_algorithm(tls, "EC");
			break;

		default:
			tls_rec_set_public_key_algorithm(tls, "Unknown");
			break;
	}

	public_key_fingerprint_hex = binary_to_hex(public_key_fingerprint, public_key_fingerprint_size);
	tls_rec_set_public_key_fingerprint(tls, public_key_fingerprint_hex);
	tls_rec_set_public_key_size(tls, EVP_PKEY_bits(pubkey));
	tls_rec_set_public_key_fingerprint_algorithm(tls, "SHA256");

	/* Read the NotBefore timestamp. */
	bio = BIO_new(BIO_s_mem());
	ASN1_TIME_print(bio, X509_get_notBefore(cert));
	length = BIO_read(bio, buffer, sizeof(buffer));
	if (length < 0) {
		ret = FALSE;
		BIO_free(bio);
		goto done;
	}
	buffer[length] = '\0';
	BIO_free(bio);
	tls_rec_set_not_before(tls, buffer);

	/* Read the NotAfter timestamp. */
	bio = BIO_new(BIO_s_mem());
	ASN1_TIME_print(bio, X509_get_notAfter(cert));
	length = BIO_read(bio, buffer, sizeof(buffer));
	if (length < 0) {
		ret = FALSE;
		BIO_free(bio);
		goto done;
	}
	buffer[length] = '\0';
	BIO_free(bio);
	tls_rec_set_not_after(tls, buffer);

done:
	g_free(cert_fingerprint_hex);
	g_free(public_key_fingerprint_hex);
	EVP_PKEY_free(pubkey);

	return ret;
}

static void set_peer_cert_chain_info(TLS_REC *tls, SSL *ssl)
{
	int nid;
	char *key = NULL;
	char *value = NULL;
	STACK_OF(X509) *chain = NULL;
	int i;
	int j;
	TLS_CERT_REC *cert_rec = NULL;
	X509_NAME *name = NULL;
	X509_NAME_ENTRY *entry = NULL;
	TLS_CERT_ENTRY_REC *tls_cert_entry_rec = NULL;
	ASN1_STRING *data = NULL;

	g_return_if_fail(tls != NULL);
	g_return_if_fail(ssl != NULL);

	chain = SSL_get_peer_cert_chain(ssl);

	if (chain == NULL)
		return;

	for (i = 0; i < sk_X509_num(chain); i++) {
		cert_rec = tls_cert_create_rec();

		/* Subject. */
		name = X509_get_subject_name(sk_X509_value(chain, i));

		for (j = 0; j < X509_NAME_entry_count(name); j++) {
			entry = X509_NAME_get_entry(name, j);

			nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry));
			key = (char *)OBJ_nid2sn(nid);

			if (key == NULL)
				key = (char *)OBJ_nid2ln(nid);

			data = X509_NAME_ENTRY_get_data(entry);
			value = (char *)ASN1_STRING_data(data);

			tls_cert_entry_rec = tls_cert_entry_create_rec(key, value);
			tls_cert_rec_append_subject_entry(cert_rec, tls_cert_entry_rec);
		}

		/* Issuer. */
		name = X509_get_issuer_name(sk_X509_value(chain, i));

		for (j = 0; j < X509_NAME_entry_count(name); j++) {
			entry = X509_NAME_get_entry(name, j);

			nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry));
			key = (char *)OBJ_nid2sn(nid);

			if (key == NULL)
				key = (char *)OBJ_nid2ln(nid);

			data = X509_NAME_ENTRY_get_data(entry);
			value = (char *)ASN1_STRING_data(data);

			tls_cert_entry_rec = tls_cert_entry_create_rec(key, value);
			tls_cert_rec_append_issuer_entry(cert_rec, tls_cert_entry_rec);
		}

		tls_rec_append_cert(tls, cert_rec);
	}
}

static void set_server_temporary_key_info(TLS_REC *tls, SSL *ssl)
{
#ifdef SSL_get_server_tmp_key
	/* Show ephemeral key information. */
	EVP_PKEY *ephemeral_key = NULL;
	char *ephemeral_key_algorithm = NULL;

	g_return_if_fail(tls != NULL);
	g_return_if_fail(ssl != NULL);

	if (SSL_get_server_tmp_key(ssl, &ephemeral_key)) {
		int keytype = EVP_PKEY_id(ephemeral_key);
		switch (keytype) {
		case EVP_PKEY_DH:
			tls_rec_set_ephemeral_key_algorithm(tls, "DH");
			tls_rec_set_ephemeral_key_size(tls, EVP_PKEY_bits(ephemeral_key));
			break;

			/* OPENSSL_NO_EC is for solaris 11.3 (2016), github ticket #598 */
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC: {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
			char cname[50];
			EVP_PKEY_get_group_name(ephemeral_key, cname, sizeof(cname), NULL);
#else
			EC_KEY *ec_key = NULL;
			char *cname = NULL;
			int nid;

			ec_key = EVP_PKEY_get1_EC_KEY(ephemeral_key);
			nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key));
			EC_KEY_free(ec_key);
			cname = (char *) OBJ_nid2sn(nid);
#endif
			ephemeral_key_algorithm = g_strdup_printf("ECDH: %s", cname);

			tls_rec_set_ephemeral_key_algorithm(tls, ephemeral_key_algorithm);
			tls_rec_set_ephemeral_key_size(tls, EVP_PKEY_bits(ephemeral_key));

			g_free_and_null(ephemeral_key_algorithm);
			break;
		}
#endif

		default:
			tls_rec_set_ephemeral_key_algorithm(tls, OBJ_nid2ln(keytype));
			tls_rec_set_ephemeral_key_size(tls, EVP_PKEY_bits(ephemeral_key));
			break;
		}

		EVP_PKEY_free(ephemeral_key);
	}
#endif /* SSL_get_server_tmp_key. */
}

GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, IPADDR *my_ip, SERVER_REC *server)
{
	GIOChannel *handle, *ssl_handle;

	handle = net_connect_ip(ip, port, my_ip);
	if (handle == NULL)
		return NULL;
	ssl_handle  = irssi_ssl_get_iochannel(handle, port, server);
	if (ssl_handle == NULL)
		g_io_channel_unref(handle);
	return ssl_handle;
}

GIOChannel *net_start_ssl(SERVER_REC *server)
{
	GIOChannel *handle, *ssl_handle;

	g_return_val_if_fail(server != NULL, NULL);

	handle = net_sendbuffer_handle(server->handle);
	if (handle == NULL)
		return NULL;

	ssl_handle  = irssi_ssl_get_iochannel(handle, server->connrec->port, server);
	return ssl_handle;
}


int irssi_ssl_handshake(GIOChannel *handle)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	int ret, err;
	const char *errstr = NULL;
	X509 *cert = NULL;
	X509_PUBKEY *pubkey = NULL;
	int pubkey_size = 0;
	unsigned char *pubkey_der = NULL;
	unsigned char *pubkey_der_tmp = NULL;
	unsigned char pubkey_fingerprint[EVP_MAX_MD_SIZE];
	unsigned int pubkey_fingerprint_size;
	unsigned char cert_fingerprint[EVP_MAX_MD_SIZE];
	unsigned int cert_fingerprint_size;
	const char *pinned_cert_fingerprint = chan->server->connrec->tls_pinned_cert;
	const char *pinned_pubkey_fingerprint = chan->server->connrec->tls_pinned_pubkey;
	TLS_REC *tls = NULL;

	ERR_clear_error();
	ret = SSL_connect(chan->ssl);
	if (ret <= 0) {
		err = SSL_get_error(chan->ssl, ret);
		switch (err) {
			case SSL_ERROR_WANT_READ:
				return 1;
			case SSL_ERROR_WANT_WRITE:
				return 3;
			case SSL_ERROR_ZERO_RETURN:
				g_warning("SSL handshake failed: %s", "server closed connection");
				return -1;
			case SSL_ERROR_SYSCALL:
				errstr = ERR_reason_error_string(ERR_get_error());
				if (errstr == NULL && ret == -1 && errno)
					errstr = strerror(errno);
				g_warning("SSL handshake failed: %s", errstr != NULL ? errstr : "server closed connection unexpectedly");
				return -1;
			default:
				errstr = ERR_reason_error_string(ERR_get_error());
				g_warning("SSL handshake failed: %s", errstr != NULL ? errstr : "unknown SSL error");
				return -1;
		}
	}

	cert = SSL_get_peer_certificate(chan->ssl);
	if (cert == NULL) {
		g_warning("TLS server supplied no certificate");
		ret = 0;
		goto done;
	}

	pubkey = X509_get_X509_PUBKEY(cert);
	if (pubkey == NULL) {
		g_warning("TLS server supplied no certificate public key");
		ret = 0;
		goto done;
	}

	if (! X509_digest(cert, EVP_sha256(), cert_fingerprint, &cert_fingerprint_size)) {
		g_warning("Unable to generate certificate fingerprint");
		ret = 0;
		goto done;
	}

	pubkey_size = i2d_X509_PUBKEY(pubkey, NULL);
	pubkey_der = pubkey_der_tmp = g_new(unsigned char, pubkey_size);
	i2d_X509_PUBKEY(pubkey, &pubkey_der_tmp);

	EVP_Digest(pubkey_der, pubkey_size, pubkey_fingerprint, &pubkey_fingerprint_size, EVP_sha256(), 0);

	tls = tls_create_rec();
	set_cipher_info(tls, chan->ssl);
	if (! set_pubkey_info(tls, cert, cert_fingerprint, cert_fingerprint_size, pubkey_fingerprint, pubkey_fingerprint_size)) {
		g_warning("Couldn't set pubkey information");
		ret = 0;
		goto done;
	}
	set_peer_cert_chain_info(tls, chan->ssl);
	set_server_temporary_key_info(tls, chan->ssl);

	/* Emit the TLS rec. */
	signal_emit("tls handshake finished", 2, chan->server, tls);

	ret = 1;

	if (pinned_cert_fingerprint != NULL && pinned_cert_fingerprint[0] != '\0') {
		ret = g_ascii_strcasecmp(pinned_cert_fingerprint, tls->certificate_fingerprint) == 0;

		if (! ret) {
			g_warning("  Pinned certificate mismatch");
			goto done;
		}
	}

	if (pinned_pubkey_fingerprint != NULL && pinned_pubkey_fingerprint[0] != '\0') {
		ret = g_ascii_strcasecmp(pinned_pubkey_fingerprint, tls->public_key_fingerprint) == 0;

		if (! ret) {
			g_warning("  Pinned public key mismatch");
			goto done;
		}
	}

	if (chan->verify) {
		ret = irssi_ssl_verify(chan->ssl, chan->ctx, chan->server->connrec->address, chan->port, cert, chan->server, tls);

		if (! ret) {
			/* irssi_ssl_verify emits a warning itself. */
			goto done;
		}
	}

done:
	tls_rec_free(tls);
	X509_free(cert);
	g_free(pubkey_der);

	return ret ? 0 : -1;
}
