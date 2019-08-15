#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http_parser.h"

#include "mows.h"

#define HTTP_MAX_URL_SIZE (16 * 1024)
#define HTTP_MAX_COOKIE_SIZE (4 * 1024)

#define MOWS_NTHREADS_DEF 100

struct mows_params
{
	unsigned int nthreads;
};

struct mows
{
	mows_params params;

	int s;

	http_parser_settings parser_settings;
};

struct mows_request
{
	char url[HTTP_MAX_URL_SIZE + 1];

	char cookie[HTTP_MAX_COOKIE_SIZE];
	int  cookie_parse_state;

	struct sockaddr_in remote;

	unsigned char method;

	int  parse_complete;
};

struct mows_thread_args
{
	int s;
	mows *m;
	struct sockaddr_in r;
};

static const struct mime_table_entry {
	const char *extension;
	const char *mime_type;
} mime_type_table[] = {
	{ "txt", "text/plain" },
	{ "c", "text/plain" },
	{ "h", "text/plain" },
	{ "html", "text/html" },
	{ "htm", "text/htm" },
	{ "css", "text/css" },
	{ "js", "text/javascript" },
	{ "gif", "image/gif" },
	{ "jpg", "image/jpeg" },
	{ "jpeg", "image/jpeg" },
	{ "png", "image/png" },
	{ "pdf", "application/pdf" },
	{ "ps", "application/postsript" },
	{ NULL, NULL }
};

static const char *
mows_guess_mime_type(const char *path)
{
	const char *last_period, *extension;
	const struct mime_table_entry *ent;

	last_period = strrchr(path, '.');
	if (!last_period || strchr(last_period, '/')) {
		goto not_found; /* no exension */
	}
	extension = last_period + 1;
	for (ent = &mime_type_table[0]; ent->extension; ent++) {
		if (!strcasecmp(ent->extension, extension)) {
			return ent->mime_type;
		}
	}

not_found:
	return "application/misc";
}

/* callbacks */
static int
mows_url_callback(http_parser *hp, const char *at, size_t length)
{
	struct mows_request *r = hp->data;

	if (length > HTTP_MAX_URL_SIZE) return 1;

	strncpy(r->url, at, length);
	r->url[length] = '\0';

	return 0;
}

/* params */
static void
mows_params_def(mows_params *p)
{
	p->nthreads = MOWS_NTHREADS_DEF;
}

mows_params *
mows_params_new(void)
{
	mows_params *p;

	p = malloc(sizeof(mows_params));
	if (!p) {
		return NULL;
	}

	mows_params_def(p);

	return p;
}

void
mows_params_free(mows_params *p)
{
	free(p);
}

void
mows_params_set(mows_params *p, MOWS_PARAM param, uint64_t val)
{
	if (param == MOWS_PARAM_NTHREADS) {
		p->nthreads = val;
	}
}

mows *
mows_new(mows_params *p, const char *addr, const int port)
{
	mows *m;
	struct sockaddr_in name;
	int one = 1;
	in_addr_t saddr;

	m = calloc(1, sizeof(mows));
	if (!m) {
		goto fail_alloc;
	}

	if (p) {
		m->params = *p;
	} else {
		mows_params_def(&m->params);
	}

	m->parser_settings.on_url = mows_url_callback;
/*
	h->parser_settings.on_message_complete = httpd_done_callback;
	h->parser_settings.on_header_field     = httpd_h_field_callback;
	h->parser_settings.on_header_value     = httpd_h_value_callback;
	h->parser_settings.on_body             = httpd_h_body_callback;
*/

	m->s = socket(AF_INET, SOCK_STREAM, 0);
	if (m->s < 0) {
		goto fail_socket;
	}

	if (setsockopt(m->s, SOL_SOCKET, SO_REUSEADDR, &one,
		sizeof(one)) != 0) {

		goto fail_set_reuse;
	}

	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_port = htons(port);
	saddr = inet_addr(addr);
	if (saddr == INADDR_NONE) {
		goto fail_inet_addr;
	}
	if (bind(m->s, (struct sockaddr *)&name, sizeof(name)) < 0) {
		goto fail_bind;
	}
	if (listen(m->s, 5) < 0) {
		goto fail_listen;
	}

	return m;

fail_listen:
fail_bind:
fail_inet_addr:
fail_set_reuse:
	close(m->s);
fail_socket:
	free(m);
fail_alloc:
	return NULL;
}

void
mows_free(mows *m)
{
	shutdown(m->s, 2);
	close(m->s);

	free(m);
}

