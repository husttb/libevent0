/*
 * Copyright (c) 2002-2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evutil.h"
#include "event.h"
#include "log.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "bufevent.h"

#define SSL_RECORD_MAX_SIZE 16384
#define SSL_ERROR 94
#define SSL_ERROR_WANT 1

struct bufevent {
	struct event_base *ev_base;

	struct event ev_read;
	struct event ev_write;

	struct evbuffer *input;
	struct evbuffer *output;

	evbufcb readcb;
	evbufcb writecb;
	everrcb errorcb;
	void *cbarg;

	int timeout_read;	/* in seconds */
	int timeout_write;	/* in seconds */

	void (*readcb_middle)(struct bufevent *bufev);
	void (*writecb_middle)(struct bufevent *bufev);

	int fd;

	SSL *ssl;

	short enabled;	/* events that are currently enabled */
};

/* prototypes */

static void bufevent_readcb_middle_plain(struct bufevent *bufev);
static void bufevent_readcb_middle_ssl(struct bufevent *bufev);
static void bufevent_readcb_start(int fd, short event, void *arg);
static void bufevent_readcb_end(struct bufevent *bufev, int res);

static void bufevent_writecb_middle_plain(struct bufevent *bufev);
static void bufevent_writecb_middle_ssl(struct bufevent *bufev);
static void bufevent_writecb_start(int fd, short event, void *arg);
static void bufevent_writecb_end(struct bufevent *bufev, int res);


static int bufevent_add(struct event *ev, int timeout)
{
	struct timeval tv, *ptv = NULL;

	if (timeout) {
		evutil_timerclear(&tv);
		tv.tv_sec = timeout;
		ptv = &tv;
	}

	return (event_add(ev, ptv));
}

static int bufevent_change_read_event(struct bufevent *bufev, short what)
{
	event_del(&bufev->ev_read);
	event_set(&bufev->ev_read, bufev->fd, what, bufevent_readcb_start, bufev);

	return bufevent_add(&bufev->ev_read, bufev->timeout_read);
}

static int bufevent_change_write_event(struct bufevent *bufev, short what)
{
	event_del(&bufev->ev_write);
	event_set(&bufev->ev_write, bufev->fd, what, bufevent_writecb_start, bufev);

	return bufevent_add(&bufev->ev_write, bufev->timeout_write);
}


static void bufevent_readcb_start(int fd, short event, void *arg)
{
	struct bufevent *bufev = arg;
	short what = EVBUFFER_READ;

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto error;
	}

	bufev->readcb_middle(bufev);
	return;

error:
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static void bufevent_readcb_end(struct bufevent *bufev, int res)
{
	short what = EVBUFFER_READ;

	if (res == -1) {
		if (errno == EAGAIN || errno == EINTR)
			goto reschedule;
		/* error case */
		what |= EVBUFFER_ERROR;
	} else if (res == 0) {
		/* eof case */
		what |= EVBUFFER_EOF;
	}

	if (res <= 0)
		goto error;

	bufevent_change_read_event(bufev, EV_READ);

	/* Invoke the user callback - must always be called last */
	if (bufev->readcb != NULL)
		(*bufev->readcb)(bufev, bufev->cbarg);
	return;

 reschedule:
	bufevent_add(&bufev->ev_read, bufev->timeout_read);
	return;

 error:
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static int bufevent_process_ssl_errors(int ret, struct bufevent* bufev, int (*bufevent_change)(struct bufevent *, short))
{
	int err = SSL_get_error(bufev->ssl, ret);
	switch (err) {
	case SSL_ERROR_ZERO_RETURN:
		errno = EOF;
		return -1;
	case SSL_ERROR_NONE:
		return 0;
	case SSL_ERROR_WANT_READ:
		bufevent_change(bufev, EV_READ);
		return SSL_ERROR_WANT;
	case SSL_ERROR_WANT_WRITE:
		bufevent_change(bufev, EV_WRITE);
		return SSL_ERROR_WANT;
	case SSL_ERROR_WANT_ACCEPT:
		event_warn("%s : SSL_WANT_ACCEPT", __func__);
		break;
	case SSL_ERROR_WANT_CONNECT:
		event_warn("%s : SSL_WANT_CONNECT", __func__);
		break;
	case SSL_ERROR_SSL:
		event_warn("%s : SSL_SSL", __func__);
		break;
	case SSL_ERROR_SYSCALL:
		event_warn("%s : SSL_SYSCAL", __func__);
		//event_del(ev);
		return -1;
	case SSL_ERROR_WANT_X509_LOOKUP:
		event_warn("%s : SSL_WANT_X509_LOOKUP", __func__);
		break;
	}
	errno = SSL_ERROR;
	return -1;
}

static void bufevent_readcb_middle_ssl(struct bufevent *bufev)
{
	if (bufev->ssl == NULL)
		goto error;
	SSL *ssl = bufev->ssl;
	char buf[SSL_RECORD_MAX_SIZE];
	int ret, err;
	do {
		ret = SSL_read(ssl, buf, SSL_RECORD_MAX_SIZE);

		err = bufevent_process_ssl_errors(ret, bufev, bufevent_change_read_event);
		if (err != 0)
			goto error;

		if (evbuffer_add(bufev->input, buf, ret) == -1)
			goto error;
	} while (SSL_pending(ssl));

	bufevent_readcb_end(bufev, ret);

	return;
error :
	if (err != SSL_ERROR_WANT)
		bufevent_readcb_end(bufev, ret);
}

static void bufevent_readcb_middle_plain(struct bufevent *bufev)
{
	int res = evbuffer_read(bufev->input, bufev->fd, -1);
	bufevent_readcb_end(bufev, res);
}

static void bufevent_writecb_start(int fd, short event, void *arg)
{
	struct bufevent *bufev = arg;
	short what = EVBUFFER_WRITE;

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto error;
	}

	if (EVBUFFER_LENGTH(bufev->output) == 0)
		return;

	bufev->writecb_middle(bufev);
	return;

 error:
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static void bufevent_writecb_end(struct bufevent *bufev, int res)
{
	short what = EVBUFFER_WRITE;
	if (res == -1) {
		if (errno == EAGAIN || errno == EINTR || errno == EINPROGRESS)
			goto reschedule;

		what |= EVBUFFER_ERROR;
		goto error;
	}

	if (EVBUFFER_LENGTH(bufev->output) != 0) {
		bufevent_change_write_event(bufev, EV_WRITE);
		return;
	} else
		event_del(&bufev->ev_write);

	if (bufev->writecb != NULL)
		(*bufev->writecb)(bufev, bufev->cbarg);

	return;

 reschedule:
	if (EVBUFFER_LENGTH(bufev->output) != 0)
		bufevent_add(&bufev->ev_write, bufev->timeout_write);
	return;

 error:
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static void bufevent_writecb_middle_plain(struct bufevent *bufev)
{
	int res = evbuffer_write(bufev->output, bufev->fd);
	bufevent_writecb_end(bufev, res);
}

static void bufevent_writecb_middle_ssl(struct bufevent *bufev)
{
	int ret = SSL_write(bufev->ssl, EVBUFFER_DATA(bufev->output), EVBUFFER_LENGTH(bufev->output));

	int err = bufevent_process_ssl_errors(ret, bufev, bufevent_change_write_event);
	if (err == SSL_ERROR_WANT)
		return;

	if (ret != -1)
		evbuffer_drain(bufev->output, ret);

	bufevent_writecb_end(bufev, ret);
}

struct bufevent * bufevent_new(int fd, evbufcb readcb, evbufcb writecb, everrcb errorcb, void *cbarg)
{
	struct bufevent *bufev;

	if ((bufev = calloc(1, sizeof(struct bufevent))) == NULL)
		return (NULL);

	if ((bufev->input = evbuffer_new()) == NULL) {
		free(bufev);
		return (NULL);
	}

	if ((bufev->output = evbuffer_new()) == NULL) {
		evbuffer_free(bufev->input);
		free(bufev);
		return (NULL);
	}

	event_set(&bufev->ev_read, fd, EV_READ, bufevent_readcb_start, bufev);
	event_set(&bufev->ev_write, fd, EV_WRITE, bufevent_writecb_start, bufev);

	bufev->readcb_middle = bufevent_readcb_middle_plain;
	bufev->writecb_middle = bufevent_writecb_middle_plain;

	bufevent_setcb(bufev, readcb, writecb, errorcb, cbarg);

	/*
	 * Set to EV_WRITE so that using bufevent_write is going to
	 * trigger a callback.  Reading needs to be explicitly enabled
	 * because otherwise no data will be available.
	 */
	bufev->enabled = EV_WRITE;

	bufev->fd = fd;

	return (bufev);
}

void bufevent_setcb(struct bufevent *bufev, evbufcb readcb, evbufcb writecb, everrcb errorcb, void *cbarg)
{
	bufev->readcb = readcb;
	bufev->writecb = writecb;
	bufev->errorcb = errorcb;

	bufev->cbarg = cbarg;
}

void bufevent_setfd(struct bufevent *bufev, int fd)
{
	event_del(&bufev->ev_read);
	event_del(&bufev->ev_write);

	event_set(&bufev->ev_read, fd, EV_READ, bufevent_readcb_start, bufev);
	event_set(&bufev->ev_write, fd, EV_WRITE, bufevent_writecb_start, bufev);
	if (bufev->ev_base != NULL) {
		event_base_set(bufev->ev_base, &bufev->ev_read);
		event_base_set(bufev->ev_base, &bufev->ev_write);
	}

	bufev->fd = fd;
}

int bufevent_priority_set(struct bufevent *bufev, int priority)
{
	if (event_priority_set(&bufev->ev_read, priority) == -1)
		return (-1);
	if (event_priority_set(&bufev->ev_write, priority) == -1)
		return (-1);

	return (0);
}

/* Closing the file descriptor is the responsibility of the caller */

void bufevent_free(struct bufevent *bufev)
{
	event_del(&bufev->ev_read);
	event_del(&bufev->ev_write);

	evbuffer_free(bufev->input);
	evbuffer_free(bufev->output);

	if (bufev->ssl != NULL)
		SSL_free(bufev->ssl);

	if (bufev->fd != -1)
		close(bufev->fd);

	free(bufev);
}

/*
 * Returns 0 on success;
 *        -1 on failure.
 */

int bufevent_write(struct bufevent *bufev, const void *data, size_t size)
{
	int res;

	res = evbuffer_add(bufev->output, data, size);

	if (res == -1)
		return (res);

	/* If everything is okay, we need to schedule a write */
	if (size > 0 && (bufev->enabled & EV_WRITE))
		bufevent_add(&bufev->ev_write, bufev->timeout_write);

	return (res);
}

int bufevent_write_buffer(struct bufevent *bufev, struct evbuffer *buf)
{
	int res;

	res = bufevent_write(bufev, buf->buffer, buf->off);
	if (res != -1)
		evbuffer_drain(buf, buf->off);

	return (res);
}

size_t bufevent_read(struct bufevent *bufev, void *data, size_t size)
{
	struct evbuffer *buf = bufev->input;

	if (buf->off < size)
		size = buf->off;

	/* Copy the available data to the user buffer */
	memcpy(data, buf->buffer, size);

	if (size)
		evbuffer_drain(buf, size);

	return (size);
}

int bufevent_enable(struct bufevent *bufev, short event)
{
	if (event & EV_READ) {
		if (bufevent_add(&bufev->ev_read, bufev->timeout_read) == -1)
			return (-1);
	}
	if (event & EV_WRITE) {
		if (bufevent_add(&bufev->ev_write, bufev->timeout_write) == -1)
			return (-1);
	}

	bufev->enabled |= event;
	return (0);
}

int bufevent_disable(struct bufevent *bufev, short event)
{
	if (event & EV_READ) {
		if (event_del(&bufev->ev_read) == -1)
			return (-1);
	}
	if (event & EV_WRITE) {
		if (event_del(&bufev->ev_write) == -1)
			return (-1);
	}

	bufev->enabled &= ~event;
	return (0);
}

/*
 * Sets the read and write timeout for a buffered event.
 */

void bufevent_settimeout(struct bufevent *bufev,
    int timeout_read, int timeout_write) {
	bufev->timeout_read = timeout_read;
	bufev->timeout_write = timeout_write;

	if (event_pending(&bufev->ev_read, EV_READ, NULL))
		bufevent_add(&bufev->ev_read, timeout_read);
	if (event_pending(&bufev->ev_write, EV_WRITE, NULL))
		bufevent_add(&bufev->ev_write, timeout_write);
}

int bufevent_base_set(struct event_base *base, struct bufevent *bufev)
{
	int res;

	bufev->ev_base = base;

	res = event_base_set(base, &bufev->ev_read);
	if (res == -1)
		return (res);

	res = event_base_set(base, &bufev->ev_write);
	return (res);
}

void bufevent_set_ssl(struct bufevent *bufev, SSL *ssl)
{
	bufev->readcb_middle = bufevent_readcb_middle_ssl;
	bufev->writecb_middle = bufevent_writecb_middle_ssl;

	bufev->ssl = ssl;
}

struct bufevent *bufevent_new_ssl(int fd, evbufcb readcb, evbufcb writecb, everrcb errorcb, void *cbarg, SSL *ssl)
{
	struct bufevent *bufev;

	bufev = bufevent_new(fd, readcb, writecb, errorcb, cbarg);
	if (bufev == NULL)
		return NULL;

	bufevent_set_ssl(bufev, ssl);

	return (bufev);
}

struct evbuffer *bufevent_get_input(struct bufevent *bufev)
{
	return bufev->input;
}

struct evbuffer *bufevent_get_output(struct bufevent *bufev)
{
	return bufev->output;
}

SSL *bufevent_get_ssl(struct bufevent *bufev)
{
	return bufev->ssl;
}
