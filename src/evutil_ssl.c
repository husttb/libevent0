/*
 * evutil_ssl.c
 *
 *  Created on: Apr 24, 2011
 *      Author: ant
 */

#include "evutil_ssl.h"
#include "log.h"
#include <event.h>

struct evutil_ssl_accept {
	accept_cb cb;
	void *cb_arg;

	SSL *ssl;

	struct event accept_event;
};

static void evutil_ssl_continue_accept(int sock, short type, void *arg)
{
	struct evutil_ssl_accept *evsa = arg;

	int r = SSL_accept(evsa->ssl);
	int err = SSL_get_error(evsa->ssl, r);
	switch (err) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_ACCEPT :
		break;
	case SSL_ERROR_WANT_READ :
		event_set(&evsa->accept_event, sock, EV_READ, evutil_ssl_continue_accept, arg);
		event_add(&evsa->accept_event, NULL);
		return;
	case SSL_ERROR_WANT_WRITE :
		event_set(&evsa->accept_event, sock, EV_WRITE, evutil_ssl_continue_accept, arg);
		event_add(&evsa->accept_event, NULL);
		return;
	case SSL_ERROR_ZERO_RETURN :
		break;
	}

	SSL_set_mode(evsa->ssl, SSL_MODE_AUTO_RETRY);

	event_del(&evsa->accept_event);

	evsa->cb(sock, evsa->ssl, evsa->cb_arg);

	free(evsa);
}

void evutil_ssl_accept(int fd, SSL_CTX *ctx, accept_cb cb, void *arg)
{
	struct evutil_ssl_accept *evsa = malloc(sizeof(struct evutil_ssl_accept));
	if (evsa == NULL) {
		event_warn("%s : malloc failed", __func__);
		return;
	}

	evsa->cb = cb;
	evsa->cb_arg = arg;

	evsa->ssl = SSL_new(ctx);
	if (evsa->ssl == NULL) {
		event_warn("%s : SSL_new failed", __func__);
		return;
	}

	int r = SSL_set_fd(evsa->ssl, fd);
	if (r == 0) {
		event_warn("%s : SSL_set_fd failed", __func__);
		return;
	}

	evutil_ssl_continue_accept(fd, 0, evsa);
}

static int password_cb(char *buf, int size, int rwflag, void *password)
{
	strncpy(buf, (char *)(password), size);
	buf[size - 1] = '\0';
	return strlen(buf);
}

SSL_CTX *evutil_ssl_init_ctx(char *certfile, char *keyfile, char *password)
{
	SSL_library_init();
	SSL_load_error_strings();

	const SSL_METHOD *meth = SSLv23_method();
	if (meth == NULL)
		return NULL;

	SSL_CTX *ctx = SSL_CTX_new(meth);
	if (ctx == NULL)
		return NULL;

	if(!(SSL_CTX_use_certificate_chain_file(ctx, certfile))) {
		event_warn("%s : Can't read certificate file", __func__);
		goto error;
	}

	SSL_CTX_set_default_passwd_cb(ctx, password_cb);
	SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)password);

	if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM))) {
		event_warn("%s : Can't read key file", __func__);
		goto error;
	}

	if(!(SSL_CTX_load_verify_locations(ctx, certfile, 0))) {
		event_warn("%s : Can't read CA list", __func__);
		goto error;
	}

	return ctx;

error :
	SSL_CTX_free(ctx);
	return NULL;
}

static void evutil_ssl_continue_connect(int sock, short type, void *arg)
{
	struct evutil_ssl_accept *evsa = arg;

	int r = SSL_connect(evsa->ssl);
	int err = SSL_get_error(evsa->ssl, r);
	switch (err) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_READ :
		event_set(&evsa->accept_event, sock, EV_READ, evutil_ssl_continue_connect, arg);
		event_add(&evsa->accept_event, NULL);
		return;
	case SSL_ERROR_WANT_WRITE :
		event_set(&evsa->accept_event, sock, EV_WRITE, evutil_ssl_continue_connect, arg);
		event_add(&evsa->accept_event, NULL);
		return;
	case SSL_ERROR_SYSCALL://ZERO_RETURN :
		SSL_free(evsa->ssl);
		evsa->ssl = NULL;
		goto out;
	}

	SSL_set_mode(evsa->ssl, SSL_MODE_AUTO_RETRY);
out:
	event_del(&evsa->accept_event);

	evsa->cb(sock, evsa->ssl, evsa->cb_arg);

	free(evsa);
}

SSL *evutil_ssl_get_ssl(SSL_CTX *ctx)
{
	return SSL_new(ctx);
}

void evutil_ssl_connect(int fd, SSL *ssl, accept_cb cb, void *arg)
{
	struct evutil_ssl_accept *evsa = malloc(sizeof(struct evutil_ssl_accept));
	if (evsa == NULL) {
		event_warn("%s : malloc failed", __func__);
		return;
	}

	evsa->cb = cb;
	evsa->cb_arg = arg;
	evsa->ssl = ssl;

	int r = SSL_set_fd(evsa->ssl, fd);
	if (r == 0) {
		event_warn("%s : SSL_set_fd failed", __func__);
		return;
	}

	evutil_ssl_continue_connect(fd, 0, evsa);
}
