/*
 * evhttps.h
 *
 *  Created on: Mar 8, 2011
 *      Author: ant
 */

#ifndef EVHTTPS_H_
#define EVHTTPS_H_

#include <evhttp.h>

int evhttp_connection_connect_ssl(struct evhttp_connection *evcon, SSL_CTX *ctx);
int evhttp_accept_socket_ssl(struct evhttp *http, int fd);
int evhttp_bind_socket_ssl(struct evhttp *http, const char *address, u_short port);

struct evhttp *evhttp_start_ssl(const char *address, u_short port, char *cert, char *keyfile, char *pass);

#endif /* EVHTTPS_H_ */
