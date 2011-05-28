/*
 * bufevent.h
 *
 *  Created on: Apr 22, 2011
 *      Author: ant
 */

#ifndef BUFEVENT_H_
#define BUFEVENT_H_

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evutil.h"
#include "event.h"

#include <openssl/ssl.h>

struct bufevent;

typedef void (*evbufcb)(struct bufevent *, void *);
typedef void (*everrcb)(struct bufevent *, short what, void *);

struct bufevent * bufevent_new(int fd, evbufcb readcb, evbufcb writecb, everrcb errorcb, void *cbarg);
struct bufevent *bufevent_new_ssl(int fd, evbufcb readcb, evbufcb writecb, everrcb errorcb, void *cbarg, SSL *ssl);

void bufevent_free(struct bufevent *bufev);

void bufevent_setcb(struct bufevent *bufev, evbufcb readcb, evbufcb writecb, everrcb errorcb, void *cbarg);
void bufevent_set_ssl(struct bufevent *bufev, SSL *ssl);
void bufevent_setfd(struct bufevent *bufev, int fd);
int bufevent_base_set(struct event_base *base, struct bufevent *bufev);
int bufevent_priority_set(struct bufevent *bufev, int priority);

int bufevent_write(struct bufevent *bufev, const void *data, size_t size);
int bufevent_write_buffer(struct bufevent *bufev, struct evbuffer *buf);

size_t bufevent_read(struct bufevent *bufev, void *data, size_t size);

int bufevent_enable(struct bufevent *bufev, short event);
int bufevent_disable(struct bufevent *bufev, short event);

void bufevent_settimeout(struct bufevent *bufev, int timeout_read, int timeout_write);

struct evbuffer *bufevent_get_input(struct bufevent *bufev);
struct evbuffer *bufevent_get_output(struct bufevent *bufev);
SSL *bufevent_get_ssl(struct bufevent *bufev);

#endif /* BUFEVENT_H_ */
