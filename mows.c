#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>
#include <errno.h>

#include "http_parser.h"

#include "mows.h"

#define HTTP_MAX_URL_SIZE (16 * 1024)
#define HTTP_MAX_COOKIE_SIZE (4 * 1024)

#define MOWS_NTHREADS_DEF 100

#define _(A) A

struct mows_params
{
	unsigned int nthreads;
};

struct mows_page_or_re
{
	int is_page;

	char url_or_re[HTTP_MAX_URL_SIZE];
	mows_page_cb cb;
};

struct mows
{
	mows_params params;
	char root[PATH_MAX];

	int s;

	http_parser_settings parser_settings;

	size_t npages;
	struct mows_page_or_re *pages;
};

struct mows_request
{
	char url[HTTP_MAX_URL_SIZE];

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

/* some parse functions */
static void
mows_percent_decode(char *s)
{
	char d[HTTP_MAX_URL_SIZE];
	size_t i, j, slen;
	char s2[3];

	s2[2] = '\0';
	slen = strlen(s);

	if (slen < 1) {
		return;
	}

	for (i=0, j=0; i<slen; i++, j++) {
		if (s[i] == '+') {
			d[j] = ' ';
		} else if (s[i] == '%') {
			unsigned int prc;

			memcpy(s2, s + i + 1, 2);
			sscanf(s2, "%x", &prc);
			d[j] = (char)prc;
			i += 2;
		} else {
			d[j] = s[i];
		}
	}
	d[j] = '\0';

	memcpy(s, d, j + 1);
}

static void
mows_parse_key_val(char *s, char *k, char *v)
{
	size_t klen, vlen;
	char *eq = strchr(s, '=');

	if (eq) {
		klen = eq - s;
	} else {
		klen = strlen(s);
	}

	strncpy(k, s, klen);
	k[klen] = '\0';

	if (eq) {
		vlen = strlen(s) - klen - 1;
		strncpy(v, s + klen + 1, vlen);
	} else {
		vlen = 0;
	}

	v[vlen] = '\0';
	mows_percent_decode(v);
}

void
mows_parse_vars(mows_request *req, char *s)
{
	size_t offset = 0;
	char key[HTTP_MAX_URL_SIZE], val[HTTP_MAX_URL_SIZE];
	char kv[sizeof(key) + sizeof(val)];

	for (;;) {
		char *amp = strchr(s + offset, '&');

		if (amp) {
			size_t kv_len = amp - s - offset;

			if (kv_len < 1) {
				break;
			}
			strncpy(kv, s + offset, kv_len);
			kv[kv_len] = '\0';
			mows_parse_key_val(kv, key, val);
			/*SMAP_INSERT_M_PTR_S(req, http_reqvars, key, val);*/
			offset += kv_len + 1;
		} else {
			if (offset < strlen(s)) {
				size_t kv_len = strlen(s) - offset;

				if (kv_len < 1) {
					break;
				}

				mows_parse_key_val(s + offset, key, val);
				/*SMAP_INSERT_M_PTR_S(req, http_reqvars, key, val);*/
				break;
			}
		}
	}
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

static int
mows_h_field_callback(http_parser *hp, const char *at, size_t length)
{
	char cookie[] = "Cookie";
	mows_request *r = hp->data;

	if (length != strlen(cookie)) {
		return 0;
	}

	if (strncmp(at, cookie, length) != 0) {
		return 0;
	}

	r->cookie_parse_state = 1;

	return 0;
}

static int
mows_h_value_callback(http_parser *hp, const char *at, size_t length)
{
	mows_request *r = hp->data;

	if (!r->cookie_parse_state) {
		return 0;
	}

	strncpy(r->cookie, at, length);
	r->cookie[length] = '\0';
	r->cookie_parse_state = 0;

	return 0;
}

static int
mows_done_callback(http_parser *hp)
{
	mows_request *r = hp->data;
	struct http_parser_url u;
	int result;

	r->parse_complete = 1;
	r->method = hp->method;
	result = http_parser_parse_url(r->url, strlen(r->url), 0, &u);
	if ((u.field_set & (1 << UF_QUERY)) != 0) {
		char   v[HTTP_MAX_URL_SIZE];

		strncpy(v, r->url + u.field_data[UF_QUERY].off,
			u.field_data[UF_QUERY].len);

		v[u.field_data[UF_QUERY].len] = '\0';
		mows_parse_vars(r, v);
		r->url[u.field_data[UF_QUERY].off - 1] = '\0';
	}

	return 0;
}

static int
mows_h_body_callback(http_parser *hp, const char *at, size_t length)
{
	mows_request *r = hp->data;
	char post_vars[HTTP_MAX_URL_SIZE];

	if (hp->method != HTTP_POST) return 0;
	if (length > sizeof(post_vars)) return 0;
	strncpy(post_vars, at, length);
	post_vars[length] = '\0';
	mows_parse_vars(r, post_vars);

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

int
mows_send_all(int sock, char *buffer, size_t len)
{
	ssize_t nsent;

	while (len > 0) {
		nsent = send(sock, buffer, len, 0);
		if(nsent == -1) {
			return 0;
		}

		buffer += nsent;
		len -= nsent;
	}

	return 1;
}

static void
mows_send_notfound(mows_request *req, const char *d, int s)
{
	char errtxt[1024*4], errbuf[1024*4];
	(void)req;

	if (errno) {
		snprintf(errtxt, sizeof(errtxt),
			_("%s<hr>Error: <b>%s</b>"), d, strerror(errno));
	} else {
		/* no error */
		snprintf(errtxt, sizeof(errtxt), _("%s<hr>"), d);
	}

	snprintf(errbuf, sizeof(errbuf),
		"HTTP/1.1 404 Not found\r\n"
		"Content-Length: %lu\r\n"
		"Content-type: text/html\r\n\r\n%s",
		(unsigned long int)strlen(errtxt), errtxt);

	mows_send_all(s, errbuf, strlen(errbuf));
}

static void
mows_send_file(mows *h, mows_request *req, int s)
{
	char fullpath[PATH_MAX], rpath[PATH_MAX];
	size_t root_len, url_len;
	FILE *f;
	char file_str[1024*8];
	size_t flen;
	char err[1024*4];

	root_len = strlen(h->root);
	url_len  = strlen(req->url);

	if (root_len == 0) {
		snprintf(err, sizeof(err), _("Root is not set "
			"and URL '%s' requested"), req->url);
		mows_send_notfound(req, err, s);
		return;
	}

	strncpy(fullpath, h->root, root_len);
	fullpath[root_len] = '\0';
	strncpy(fullpath + root_len, req->url, url_len + 1);

	if (realpath(fullpath, rpath) == NULL) {
		snprintf(err, sizeof(err), _("Incorrect path: '%s'"),
			fullpath);
		mows_send_notfound(req, err, s);
		return;
	}

	if (strncmp(fullpath, rpath, root_len) != 0) {
		snprintf(err, sizeof(err), _("Incorrect path: '%s'"), rpath);
		mows_send_notfound(req, err, s);
		return;
	}

	f = fopen(rpath, "rb");
	if (!f) {
		snprintf(err, sizeof(err), _("Can't open file: '%s'"), rpath);
		mows_send_notfound(req, err, s);
		return;
	}

	fseek(f, 0, SEEK_END);
	flen = ftell(f);
	rewind(f);

	snprintf(file_str, sizeof(file_str),
		"HTTP/1.1 200 Ok\r\n"
		"Content-type: %s\r\n"
		"Content-Length: %lu\r\n\r\n",
		mows_guess_mime_type(rpath), (long unsigned int)flen);

	mows_send_all(s, file_str, strlen(file_str));

	for (;;) {
		size_t bytes;

		bytes = fread(file_str, 1, sizeof(file_str), f);
		mows_send_all(s, file_str, bytes);
		if (feof(f)) {
			break;
		}
	}

	fclose(f);
}

static void *
mows_accept_request(void *arg)
{
	mows_request req;
	struct mows_thread_args *ta = arg;
	mows *m = ta->m;
	int s = ta->s;
	struct sockaddr_in r = ta->r;

	char buf[HTTP_MAX_HEADER_SIZE];
	http_parser *parser;

	free(ta);

	memset(&req, 0, sizeof(mows_request));
	parser = malloc(sizeof(http_parser));
	http_parser_init(parser, HTTP_REQUEST);

	req.parse_complete = 0;
	parser->data = &req;
	req.remote = r;

	for (;;) {
		ssize_t recved, nparsed;

		recved = recv(s, buf, HTTP_MAX_HEADER_SIZE, 0);
		if (recved <= 0) break;

		nparsed = http_parser_execute(parser, &m->parser_settings,
			buf, recved);
		if (nparsed != recved) break;

		if (req.parse_complete) {
			size_t i;
			int pfound = 0;
			mows_page_cb cb = NULL;

			for (i=0; i<m->npages; i++) {
				/* search for URL in registered dynamic pages */
				if (strcmp(req.url, m->pages[i].url_or_re)
					== 0) {

					cb(m, &req, s);
					pfound = 1;
					break;
				}
			}
			if (!pfound) {
				mows_send_file(m, &req, s);
			}

			req.cookie[0] = '\0';
		}
	}
	free(parser);

	return NULL;
}

int
mows_start(mows *m)
{
	struct sockaddr_in remote_addr;
	int client_sock;
	pthread_t newthread;
	socklen_t remote_addr_len = sizeof(remote_addr);

	for (;;) {
		struct mows_thread_args *ta;

		client_sock = accept(m->s, (struct sockaddr *)&remote_addr,
			&remote_addr_len);

		if (client_sock == -1) {
			goto fail_accept;
		}

		ta = malloc(sizeof(struct mows_thread_args));
		ta->m = m;
		ta->s = client_sock;
		ta->r = remote_addr;

		if (pthread_create(&newthread, NULL, mows_accept_request, ta)
			!= 0) {

			free(ta);
			goto fail_new_thread;
		}

		pthread_detach(newthread); /* XXX: ??? */
	}
	return 1;

fail_new_thread:
	/* XXX: close socket? */
fail_accept:
	return 0;
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

	m->parser_settings.on_url              = mows_url_callback;
	m->parser_settings.on_message_complete = mows_done_callback;
	m->parser_settings.on_header_field     = mows_h_field_callback;
	m->parser_settings.on_header_value     = mows_h_value_callback;
	m->parser_settings.on_body             = mows_h_body_callback;

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

int
mows_set_root(mows *m, const char *dir)
{
	int r = 0;

	if (realpath(dir, m->root) == NULL) {
		r = errno;
	}

	return r;
}

