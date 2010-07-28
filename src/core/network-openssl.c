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
#include "network.h"
#include "misc.h"

#ifdef HAVE_OPENSSL

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ssl i/o channel object */
typedef struct
{
	GIOChannel pad;
	gint fd;
	GIOChannel *giochan;
	SSL *ssl;
	SSL_CTX *ctx;
	unsigned int verify:1;
	const char *hostname;
} GIOSSLChannel;

static int ssl_inited = FALSE;

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
		free(cert_subject_cn);
	}

	return matched;
}

static gboolean irssi_ssl_verify(SSL *ssl, SSL_CTX *ctx, const char* hostname, X509 *cert)
{
	long result;

	result = SSL_get_verify_result(ssl);
	if (result != X509_V_OK) {
		unsigned char md[EVP_MAX_MD_SIZE];
		unsigned int n;
		char *str;

		g_warning("Could not verify SSL servers certificate: %s",
				X509_verify_cert_error_string(result));
		if ((str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0)) == NULL)
			g_warning("  Could not get subject-name from peer certificate");
		else {
			g_warning("  Subject : %s", str);
			free(str);
		}
		if ((str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0)) == NULL)
			g_warning("  Could not get issuer-name from peer certificate");
		else {
			g_warning("  Issuer  : %s", str);
			free(str);
		}
		if (! X509_digest(cert, EVP_md5(), md, &n))
			g_warning("  Could not get fingerprint from peer certificate");
		else {
			char hex[] = "0123456789ABCDEF";
			char fp[EVP_MAX_MD_SIZE*3];
			if (n < sizeof(fp)) {
				unsigned int i;
				for (i = 0; i < n; i++) {
					fp[i*3+0] = hex[(md[i] >> 4) & 0xF];
					fp[i*3+1] = hex[(md[i] >> 0) & 0xF];
					fp[i*3+2] = i == n - 1 ? '\0' : ':';
				}
				g_warning("  MD5 Fingerprint : %s", fp);
			}
		}
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

static gboolean irssi_ssl_init(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	ssl_inited = TRUE;

	return TRUE;

}

static GIOChannel *irssi_ssl_get_iochannel(GIOChannel *handle, const char *hostname, const char *mycert, const char *mypkey, const char *cafile, const char *capath, gboolean verify)
{
	GIOSSLChannel *chan;
	GIOChannel *gchan;
	int fd;
	SSL *ssl;
	SSL_CTX *ctx = NULL;

	g_return_val_if_fail(handle != NULL, NULL);

	if(!ssl_inited && !irssi_ssl_init())
		return NULL;

	if(!(fd = g_io_channel_unix_get_fd(handle)))
		return NULL;

	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL) {
		g_error("Could not allocate memory for SSL context");
		return NULL;
	}
	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);

	if (mycert && *mycert) {
		char *scert = NULL, *spkey = NULL;
		scert = convert_home(mycert);
		if (mypkey && *mypkey)
			spkey = convert_home(mypkey);
		if (! SSL_CTX_use_certificate_file(ctx, scert, SSL_FILETYPE_PEM))
			g_warning("Loading of client certificate '%s' failed", mycert);
		else if (! SSL_CTX_use_PrivateKey_file(ctx, spkey ? spkey : scert, SSL_FILETYPE_PEM))
			g_warning("Loading of private key '%s' failed", mypkey ? mypkey : mycert);
		else if (! SSL_CTX_check_private_key(ctx))
			g_warning("Private key does not match the certificate");
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
			g_warning("Could not load CA list for verifying SSL server certificate");
			g_free(scafile);
			g_free(scapath);
			SSL_CTX_free(ctx);
			return NULL;
		}
		g_free(scafile);
		g_free(scapath);
		verify = TRUE;
	} else {
		if (!SSL_CTX_set_default_verify_paths(ctx))
			g_warning("Could not load default certificates");
	}

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

	SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE |
			SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	chan = g_new0(GIOSSLChannel, 1);
	chan->fd = fd;
	chan->giochan = handle;
	chan->ssl = ssl;
	chan->ctx = ctx;
	chan->verify = verify;
	chan->hostname = hostname;

	gchan = (GIOChannel *)chan;
	gchan->funcs = &irssi_ssl_channel_funcs;
	g_io_channel_init(gchan);
	gchan->is_readable = gchan->is_writeable = TRUE;
	gchan->use_buffer = FALSE;

	return gchan;
}

GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, const char* hostname, IPADDR *my_ip, const char *cert, const char *pkey, const char *cafile, const char *capath, gboolean verify)
{
	GIOChannel *handle, *ssl_handle;

	handle = net_connect_ip(ip, port, my_ip);
	if (handle == NULL)
		return NULL;
	ssl_handle  = irssi_ssl_get_iochannel(handle, hostname, cert, pkey, cafile, capath, verify);
	if (ssl_handle == NULL)
		g_io_channel_unref(handle);
	return ssl_handle;
}

int irssi_ssl_handshake(GIOChannel *handle)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	int ret, err;
	X509 *cert;
	const char *errstr;

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
				if (errstr == NULL && ret == -1)
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
		g_warning("SSL server supplied no certificate");
		return -1;
	}
	ret = !chan->verify || irssi_ssl_verify(chan->ssl, chan->ctx, chan->hostname, cert);
	X509_free(cert);
	return ret ? 0 : -1;
}

#else /* HAVE_OPENSSL */

GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, const char* hostname, IPADDR *my_ip, const char *cert, const char *pkey, const char *cafile, const char *capath, gboolean verify)
{
	g_warning("Connection failed: SSL support not enabled in this build.");
	errno = ENOSYS;
	return NULL;
}

#endif /* ! HAVE_OPENSSL */
