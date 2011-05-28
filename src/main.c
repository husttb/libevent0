/*
 * main.c
 *
 *  Created on: May 28, 2011
 *      Author: ant
 */

/*
 * main.c
 *
 *  Created on: Nov 30, 2010
 *      Author: ant
 */
#include <string.h>
#include "stdio.h"
#include "evhttp.h"
#include "event.h"

void req_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *buf = evbuffer_new();

	evbuffer_add_printf(buf, "Hello, from server!");

	evhttp_send_reply(req, 200, "OK", buf);

	evbuffer_free(buf);
}

static void stop(int fd, short tv, void *arg)
{
	event_loopbreak();
}

int main()
{
	event_init();

	struct evhttp *http = evhttp_start("127.0.0.1", 8010);
	evhttp_set_cb(http, "/hello", req_cb, NULL);

	struct timeval tv = {25, 0};
	event_once(-1, EV_TIMEOUT, stop, NULL, &tv);

	event_dispatch();

	evhttp_free(http);

	return 0;

}
