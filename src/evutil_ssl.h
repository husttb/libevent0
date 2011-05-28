/*
 * evutil_ssl.h
 *
 *  Created on: Apr 24, 2011
 *      Author: ant
 */

#ifndef EVUTIL_SSL_H_
#define EVUTIL_SSL_H_

#include <openssl/ssl.h>

typedef void (*accept_cb)(int fd, SSL *ssl, void *arg);

void evutil_ssl_accept(int fd, SSL_CTX *ctx, accept_cb cb, void *arg);

SSL_CTX *evutil_ssl_init_ctx(char *certfile, char *keyfile, char *password);

SSL *evutil_ssl_get_ssl(SSL_CTX *ctx);

void evutil_ssl_connect(int fd, SSL *ssl, accept_cb cb, void *arg);

#endif /* EVUTIL_SSL_H_ */
