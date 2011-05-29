/*
 * main.c
 *
 *  Created on: May 24, 2010
 *      Author: ant /add jrpc to libraries
 */

#include <stdio.h>
#include <event0/evhttp.h>
#include <event.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

int get_file_size(char *path)
{
	struct stat stat_uri;
	if (stat(path, &stat_uri) == -1) {
		return -1;
	}

	return stat_uri.st_size;
}

static int read_file(int fd, void *buf, int length)
{
	int ret;
	while (length > 0 && (ret = read(fd, buf, length)) != 0) {
		if (ret == -1) {
			if (errno == EINTR)
				continue;

			goto error;
		}

		length -= ret;
		buf += ret;
	}

	if (length > 0)
		goto error;

	return 0;

error:
	return -1;
}

void *get_file_content(char *path)
{
	int len_file = get_file_size(path);
	if (len_file == -1) {
		return NULL;
	}

	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		return NULL;
	}

	void *buf = malloc(len_file + 1);
	if (buf == NULL) {
		return NULL;
	}

	int ret = read_file(fd, buf, len_file);
	((char *)buf)[len_file] = '\0';

	close(fd);

	if (ret == -1) {
		free(buf);
		return NULL;
	}

	return buf;
}

static int write_file(int fd, void *data, int len)
{
	int ret;
	while (len > 0 && (ret = write(fd, data, len)) != 0) {
		if (ret == -1) {
			if (errno == EINTR)
				continue;

			break;
		}

		len -= ret;
		data += ret;
	}

	return len > 0 ? -1 : 0;
}

int put_file_content(char *path, void *data, int size)
{
	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR |
														S_IRGRP | S_IWGRP |
														S_IROTH | S_IWOTH);
	if (fd == -1) {
		return -1;
	}

	int ret = write_file(fd, data, size);

	close(fd);

	return ret;
}

int string_ends_by(char *str, char *end)
{
	char *loc = strstr(str, end);
	return (loc != NULL && strlen(loc) == strlen(end));
}

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <memory.h>
#include <unistd.h>
#include <fcntl.h>

#define HTTP_HOST "127.0.0.1"
#define HTTP_PORT 8080

#define SSL_CERT "serv.pem"
#define SSL_KEYFILE "serv.pem"
#define SSL_PASSWD "1234"

#define GET_DEVICES_METHOD "get_devices"
#define GET_DEVICE_STATUS_METHOD "get_device_status"
#define SET_DEVICE_STATUS_METHOD "set_device_status"

#define JSON_RPC_ENDPOINT "/devices"
#define WS_ENDPOINT "/ws"

#define HTTP_OK_CODE 200
#define HTTP_NOT_FOUND_CODE 404
#define HTTP_INTERNAL_ERROR_CODE 500
#define HTTP_OK_REASON "OK"
#define HTTP_NOT_FOUND_REASON "Not Found"
#define HTTP_INTERNAL_ERROR_REASON "Internal Error"

#define CSS_POSTFIX ".css"
#define JS_POSTFIX ".js"


#define DEVICES_FILE "devices"

static void resource_handler(struct evhttp_request *req, void *arg)
{
	if (strcmp(req->uri, JSON_RPC_ENDPOINT) == 0 || strcmp(req->uri, WS_ENDPOINT) == 0)
		return;

	char *path = req->uri + sizeof(char);//skip leading slash

	int len = get_file_size(path);
	if (len == -1) {
		evhttp_send_error(req, HTTP_NOT_FOUND_CODE, HTTP_NOT_FOUND_REASON);
		return;
	}

	void *buf = get_file_content(path);
	if (buf == NULL)
		goto error;

	struct evbuffer *evbuf = evbuffer_new();
	if (evbuf == NULL)
		goto error;

	if (evbuffer_add(evbuf, buf, len) == -1) {
		evbuffer_free(evbuf);
		goto error;
	}

	if (string_ends_by(path, CSS_POSTFIX)) {
		evhttp_add_header(req->output_headers, "Content-Type", "text/css");
	}

	if (string_ends_by(path, JS_POSTFIX)) {
		evhttp_add_header(req->output_headers, "Content-Type", "text/javascript");
	}

	evhttp_send_reply(req, HTTP_OK_CODE, HTTP_OK_REASON, evbuf);

	free(buf);
	free(evbuf);

	return;

error:
	free(buf);
	evhttp_send_error(req, HTTP_INTERNAL_ERROR_CODE, HTTP_INTERNAL_ERROR_REASON);
}

int main()
{
	event_init();

	struct evhttp *eh = evhttp_start("192.168.0.100", HTTP_PORT);
//	struct evhttp *ehs = evhttp_start_ssl(HTTP_HOST, 8080, SSL_CERT, SSL_KEYFILE, SSL_PASSWD);

	evhttp_set_gencb(eh, resource_handler, NULL);

	event_dispatch();

	return 0;
}
