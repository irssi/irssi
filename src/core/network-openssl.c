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

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "network.h"

#ifdef HAVE_OPENSSL

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ssl read */
GIOError irssi_ssl_read(GIOChannel *, gchar *, guint, guint *);
/* ssl write */
GIOError irssi_ssl_write(GIOChannel *, gchar *, guint, guint*);
/* ssl seek */
GIOError irssi_ssl_seek(GIOChannel *, gint, GSeekType);
/* ssl close */
void irssi_ssl_close(GIOChannel *);
#if GLIB_MAJOR_VERSION < 2
/* ssl create watch */
guint irssi_ssl_create_watch(GIOChannel *, gint, GIOCondition, GIOFunc, gpointer, GDestroyNotify);
#else
GSource *irssi_ssl_create_watch(GIOChannel *, GIOCondition);
#endif
/* ssl free */
void irssi_ssl_free(GIOChannel *);

/* ssl i/o channel object */
typedef struct
{
	GIOChannel pad;
	gint fd;
	GIOChannel *giochan;
	SSL *ssl;
	X509 *cert;
} GIOSSLChannel;
	
/* ssl function pointers */
GIOFuncs irssi_ssl_channel_funcs =
{
	irssi_ssl_read,
	irssi_ssl_write,
	irssi_ssl_seek,
	irssi_ssl_close,
	irssi_ssl_create_watch,
	irssi_ssl_free
};

SSL_CTX *ssl_ctx = NULL;

#ifdef G_CAN_INLINE
G_INLINE_FUNC
#endif
gint ssl_errno(gint e)
{
	switch(e)
	{
		case EINVAL:
			return G_IO_ERROR_INVAL;
		case EINTR:
		case EAGAIN:
			return G_IO_ERROR_AGAIN;
		default:
			return G_IO_ERROR_INVAL;
	}
	/*UNREACH*/
	return -1;
}

gboolean irssi_ssl_cert_step(GIOSSLChannel *chan)
{
	gint err;
	switch(err = SSL_do_handshake(chan->ssl))
	{
		case 1:
			if(!(chan->cert = SSL_get_peer_certificate(chan->ssl)))
			{
				g_warning("SSL server supplied no certificate");
				return G_IO_ERROR_INVAL;
			}
			return G_IO_ERROR_NONE;
		default:
			if(SSL_get_error(chan->ssl, err) == SSL_ERROR_WANT_READ)
				return G_IO_ERROR_AGAIN;
			return ssl_errno(errno);
	}
	/*UNREACH*/
	return -1;
}

GIOError irssi_ssl_read(GIOChannel *handle, gchar *buf, guint len, guint *ret)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	gint err;
	
	if(chan->cert == NULL)
	{
		gint cert_err = irssi_ssl_cert_step(chan);
		if(cert_err != G_IO_ERROR_NONE)
			return cert_err;
	}
	
	err = SSL_read(chan->ssl, buf, len);
	if(err < 0)
	{
		*ret = 0;
		if(SSL_get_error(chan->ssl, err) == SSL_ERROR_WANT_READ)
			return G_IO_ERROR_AGAIN;
		return ssl_errno(errno);
	}
	else
	{
		*ret = err;
		return G_IO_ERROR_NONE;
	}
	/*UNREACH*/
	return -1;
}

GIOError irssi_ssl_write(GIOChannel *handle, gchar *buf, guint len, guint *ret)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	gint err;

	if(chan->cert == NULL)
	{
		gint cert_err = irssi_ssl_cert_step(chan);
		if(cert_err != G_IO_ERROR_NONE)
			return cert_err;
	}
	

	err = SSL_write(chan->ssl, (const char *)buf, len);
	if(err < 0)
	{
		*ret = 0;
		if(SSL_get_error(chan->ssl, err) == SSL_ERROR_WANT_READ)
			return G_IO_ERROR_AGAIN;
		return ssl_errno(errno);
	}
	else
	{
		*ret = err;
		return G_IO_ERROR_NONE;
	}
	/*UNREACH*/
	return -1;
}

GIOError irssi_ssl_seek(GIOChannel *handle, gint offset, GSeekType type)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	GIOError e;
	e = g_io_channel_seek(chan->giochan, offset, type);
	return (e == G_IO_ERROR_NONE) ? G_IO_ERROR_NONE : G_IO_ERROR_INVAL;
}

void irssi_ssl_close(GIOChannel *handle)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	g_io_channel_close(chan->giochan);
}

#if GLIB_MAJOR_VERSION < 2
guint irssi_ssl_create_watch(GIOChannel *handle, gint priority, GIOCondition cond,
			     GIOFunc func, gpointer data, GDestroyNotify notify)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;

	return chan->giochan->funcs->io_add_watch(handle, priority, cond, func, data, notify);
}
#else
GSource *irssi_ssl_create_watch(GIOChannel *handle, GIOCondition cond)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;

	return chan->giochan->funcs->io_create_watch(handle, cond);
}
#endif

void irssi_ssl_free(GIOChannel *handle)
{
	GIOSSLChannel *chan = (GIOSSLChannel *)handle;
	g_io_channel_unref(chan->giochan);
	SSL_free(chan->ssl);
	g_free(chan);
}

gboolean irssi_ssl_init(void)
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

GIOChannel *irssi_ssl_get_iochannel(GIOChannel *handle)
{
	GIOSSLChannel *chan;
	GIOChannel *gchan;
	int err, fd;
	SSL *ssl;
	X509 *cert = NULL;

	g_return_val_if_fail(handle != NULL, NULL);
	
	if(!ssl_ctx && !irssi_ssl_init())
		return NULL;

	if(!(fd = g_io_channel_unix_get_fd(handle)))
		return NULL;

	if(!(ssl = SSL_new(ssl_ctx)))
	{
		g_warning("Failed to allocate SSL structure");
		return NULL;
	}

	if(!(err = SSL_set_fd(ssl, fd)))
	{
		g_warning("Failed to associate socket to SSL stream");
		return NULL;
	}

	if((err = SSL_connect(ssl)) <= 0)
	{
		switch(err = SSL_get_error(ssl, err))
		{
			case SSL_ERROR_SYSCALL:
				if(errno == EINTR || errno == EAGAIN)
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
					break;
			default:
					return NULL;
		}
	}
	else if(!(cert = SSL_get_peer_certificate(ssl)))
	{
		g_warning("SSL server supplied no certificate");
		return NULL;
	}
	else
		X509_free(cert);

	chan = g_new0(GIOSSLChannel, 1);
	chan->fd = fd;
	chan->giochan = handle;
	chan->ssl = ssl;
	chan->cert = cert;
	g_io_channel_ref(handle);

	gchan = (GIOChannel *)chan;
	gchan->funcs = &irssi_ssl_channel_funcs;
	g_io_channel_init(gchan);
	
	return gchan;
}

GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, IPADDR *my_ip)
{
	GIOChannel *gret = net_connect_ip(ip, port, my_ip);
	gret = irssi_ssl_get_iochannel(gret);
	return gret;
}

#else /* HAVE_OPENSSL */

GIOChannel *net_connect_ip_ssl(IPADDR *ip, int port, IPADDR *my_ip)
{
	g_warning("Connection failed: SSL support not enabled in this build.");
	errno = ENOSYS;
	return NULL;
}

#endif /* ! HAVE_OPENSSL */
