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
} GIOSSLChannel;
	
static SSL_CTX *ssl_ctx = NULL;

static void irssi_ssl_free(GIOChannel *handle)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	g_io_channel_unref(chan->giochan);
	SSL_free(chan->ssl);
	if (chan->ctx != ssl_ctx)
		SSL_CTX_free(chan->ctx);
	g_free(chan);
}

static gboolean irssi_ssl_verify(SSL *ssl, SSL_CTX *ctx, X509 *cert)
{
	if (SSL_get_verify_result(ssl) != X509_V_OK) {
		unsigned char md[EVP_MAX_MD_SIZE];
		unsigned int n;
		char *str;

		g_warning("Could not verify SSL servers certificate:");
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
	}
	return TRUE;
}

static GIOStatus ssl_errno(gint e)
{
	switch(e)
	{
		case EINVAL:
			return G_IO_STATUS_ERROR;
		case EINTR:
		case EAGAIN:
			return G_IO_STATUS_AGAIN;
		default:
			return G_IO_STATUS_ERROR;
	}
	/*UNREACH*/
	return G_IO_STATUS_ERROR;
}

static GIOStatus irssi_ssl_read(GIOChannel *handle, gchar *buf, gsize len, gsize *ret, GError **gerr)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	gint err;
	
	err = SSL_read(chan->ssl, buf, len);
	if(err < 0)
	{
		*ret = 0;
		if(SSL_get_error(chan->ssl, err) == SSL_ERROR_WANT_READ)
			return G_IO_STATUS_AGAIN;
		return ssl_errno(errno);
	}
	else
	{
		*ret = err;
		return G_IO_STATUS_NORMAL;
	}
	/*UNREACH*/
	return G_IO_STATUS_ERROR;
}

static GIOStatus irssi_ssl_write(GIOChannel *handle, const gchar *buf, gsize len, gsize *ret, GError **gerr)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	gint err;

	err = SSL_write(chan->ssl, (const char *)buf, len);
	if(err < 0)
	{
		*ret = 0;
		if(SSL_get_error(chan->ssl, err) == SSL_ERROR_WANT_READ)
			return G_IO_STATUS_AGAIN;
		return ssl_errno(errno);
	}
	else
	{
		*ret = err;
		return G_IO_STATUS_NORMAL;
	}
	/*UNREACH*/
	return G_IO_STATUS_ERROR;
}

static GIOStatus irssi_ssl_seek(GIOChannel *handle, gint64 offset, GSeekType type, GError **gerr)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	GIOError e;
	e = g_io_channel_seek(chan->giochan, offset, type);
	return (e == G_IO_ERROR_NONE) ? G_IO_STATUS_NORMAL : G_IO_STATUS_ERROR;
}

static GIOStatus irssi_ssl_close(GIOChannel *handle, GError **gerr)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	g_io_channel_close(chan->giochan);

	return G_IO_STATUS_NORMAL;
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
	
	ssl_ctx = SSL_CTX_new(SSLv23_client_method());
	if(!ssl_ctx)
	{
		g_error("Initialization of the SSL library failed");
		return FALSE;
	}

	return TRUE;

}

static GIOChannel *irssi_ssl_get_iochannel(GIOChannel *handle, const char *mycert, const char *mypkey, const char *cafile, const char *capath, gboolean verify)
{
	GIOSSLChannel *chan;
	GIOChannel *gchan;
	int err, fd;
	SSL *ssl;
	SSL_CTX *ctx = NULL;

	g_return_val_if_fail(handle != NULL, NULL);
	
	if(!ssl_ctx && !irssi_ssl_init())
		return NULL;

	if(!(fd = g_io_channel_unix_get_fd(handle)))
		return NULL;

	if (mycert && *mycert) {	
		char *scert = NULL, *spkey = NULL;
		if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
			g_error("Could not allocate memory for SSL context");
			return NULL;
		}
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
		if (! ctx && (ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
			g_error("Could not allocate memory for SSL context");
			return NULL;
		}
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
	}

	if (ctx == NULL)
		ctx = ssl_ctx;
	
	if(!(ssl = SSL_new(ctx)))
	{
		g_warning("Failed to allocate SSL structure");
		return NULL;
	}

	if(!(err = SSL_set_fd(ssl, fd)))
	{
		g_warning("Failed to associate socket to SSL stream");
		SSL_free(ssl);
		if (ctx != ssl_ctx)
			SSL_CTX_free(ctx);
		return NULL;
	}

	chan = g_new0(GIOSSLChannel, 1);
	chan->fd = fd;
	chan->giochan = handle;
	chan->ssl = ssl;
	chan->ctx = ctx;
	chan->verify = verify;

	gchan = (GIOChannel *)chan;
	gchan->funcs = &irssi_ssl_channel_funcs;
	g_io_channel_init(gchan);
	
	return gchan;
}

GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, IPADDR *my_ip, const char *cert, const char *pkey, const char *cafile, const char *capath, gboolean verify)
{
	GIOChannel *handle, *ssl_handle;

	handle = net_connect_ip(ip, port, my_ip);
	if (handle == NULL)
		return NULL;
	ssl_handle  = irssi_ssl_get_iochannel(handle, cert, pkey, cafile, capath, verify);
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
		if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
			errstr = ERR_reason_error_string(ERR_get_error());
			g_warning("SSL handshake failed: %s", errstr != NULL ? errstr : "server closed connection");
			return -1;
		}
		return err == SSL_ERROR_WANT_READ ? 1 : 3;
	}

	cert = SSL_get_peer_certificate(chan->ssl);
	if (cert == NULL) {
		g_warning("SSL server supplied no certificate");
		return -1;
	}
	ret = !chan->verify || irssi_ssl_verify(chan->ssl, chan->ctx, cert);
	X509_free(cert);
	return ret ? 0 : -1;
}

#else /* HAVE_OPENSSL */

GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, IPADDR *my_ip, const char *cert, const char *pkey, const char *cafile, const char *capath, gboolean verify)
{
	g_warning("Connection failed: SSL support not enabled in this build.");
	errno = ENOSYS;
	return NULL;
}

#endif /* ! HAVE_OPENSSL */
