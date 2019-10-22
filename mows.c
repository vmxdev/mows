/*
 * mows
 *
 * Copyright (c) 2019, Vladimir Misyurov
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

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
#include <regex.h>

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

	char url[HTTP_MAX_URL_SIZE];
	regex_t re;
	mows_page_cb cb;
};

struct mows
{
	mows_params params;
	char root[PATH_MAX];

	int s;

	int bg;             /* run in background */
	int stop;           /* stop request */
	pthread_t bgthread; /* background thread id */

	http_parser_settings parser_settings;

	size_t npages;
	struct mows_page_or_re *pages;
};

struct mows_keyval
{
	char *name;
	char *val;
};

struct mows_request
{
	char url[HTTP_MAX_URL_SIZE];

	struct sockaddr_in remote;

	int method;

	int parse_complete;

	/* request variables (GET or POST) */
	size_t nvars;
	struct mows_keyval *vars;

	/* HTTP headers */
	size_t nheaders;
	struct mows_keyval *headers;
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

static int
mows_add_var(mows_request *req, const char *name, const char *val)
{
	struct mows_keyval *tmp_ptr;
	struct mows_keyval v;

	if (!(v.name = strdup(name))) {
		return 0;
	}
	if (!(v.val = strdup(val))) {
		free(v.name);
		return 0;
	}

	tmp_ptr = realloc(req->vars, (req->nvars + 1)
		* sizeof(struct mows_keyval));
	if (!tmp_ptr) {
		return 0;
	}
	req->vars = tmp_ptr;

	req->vars[req->nvars] = v;
	req->nvars++;

	return 1;
}

static void
mows_free_kv(size_t *n, struct mows_keyval **kv)
{
	size_t i;

	for (i=0; i<*n; i++) {
		free(((*kv)[i]).name);
		free(((*kv)[i]).val);
	}

	free(*kv);

	*kv = NULL;
	*n = 0;
}

static void
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
			mows_add_var(req, key, val);
			offset += kv_len + 1;
		} else {
			if (offset < strlen(s)) {
				size_t kv_len = strlen(s) - offset;

				if (kv_len < 1) {
					break;
				}

				mows_parse_key_val(s + offset, key, val);
				mows_add_var(req, key, val);
			}
			break;
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
	struct mows_keyval *tmp_ptr, v;
	mows_request *req = hp->data;

	v.val = NULL;
	v.name = malloc(length + 1);
	if (!v.name) {
		return 1;
	}
	memcpy(v.name, at, length);
	v.name[length] = '\0';

	tmp_ptr = realloc(req->headers, (req->nheaders + 1)
		* sizeof(struct mows_keyval));
	if (!tmp_ptr) {
		return 1;
	}
	req->headers = tmp_ptr;

	req->headers[req->nheaders] = v;
	req->nheaders++;

	return 0;
}

static int
mows_h_value_callback(http_parser *hp, const char *at, size_t length)
{
	mows_request *req = hp->data;
	struct mows_keyval *hdr;

	if (req->nheaders == 0) {
		return 1;
	}

	hdr = &req->headers[req->nheaders - 1];
	hdr->val = malloc(length + 1);
	if (!hdr->val) {
		return 1;
	}
	memcpy(hdr->val, at, length);
	hdr->val[length] = '\0';

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

	if (hp->method != HTTP_POST) {
		return 0;
	}
	if (length > sizeof(post_vars)) {
		return 0;
	}
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

/* try to send all buffer using multiple `send()` if needed */
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

	f = fopen(rpath, "r+b");
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

		mows_free_kv(&(req.nvars), &(req.vars));
		mows_free_kv(&(req.nheaders), &(req.headers));
		recved = recv(s, buf, HTTP_MAX_HEADER_SIZE, 0);
		if (recved <= 0) {
			break;
		}

		nparsed = http_parser_execute(parser, &m->parser_settings,
			buf, recved);
		if (nparsed != recved) {
			break;
		}

		if (req.parse_complete) {
			size_t i;
			int pfound = 0;

			for (i=0; i<m->npages; i++) {
				/* search for URL (or regex) in registered
				dynamic pages */
				if (m->pages[i].is_page) {
					/* direct URL */
					if (strcmp(req.url, m->pages[i].url)
						== 0) {

						m->pages[i].cb(m, &req, s);
						pfound = 1;
						break;
					}
				} else {
					/* regex */
					if (regexec(&m->pages[i].re, req.url,
						0, NULL, 0) == 0) {

						m->pages[i].cb(m, &req, s);
						pfound = 1;
						break;
					}
				}
			}
			if (!pfound) {
				/* no matches in dynamic pages */
				mows_send_file(m, &req, s);
			}
		}
	}

	mows_free_kv(&(req.nvars), &(req.vars));
	mows_free_kv(&(req.nheaders), &(req.headers));

	free(parser);
	close(s);

	return NULL;
}

static void *
mows_work_loop(void *arg)
{
	pthread_t connthread;
	int client_sock;
	struct sockaddr_in remote_addr;
	socklen_t remote_addr_len = sizeof(remote_addr);

	mows *m = (mows *)arg;

	for (;;) {
		struct mows_thread_args *ta;
		int rc;

		client_sock = accept(m->s, (struct sockaddr *)&remote_addr,
			&remote_addr_len);

		if (m->stop) {
			/* server stop requested */
			break;
		}

		if (client_sock == -1) {
			break;
		}

		ta = malloc(sizeof(struct mows_thread_args));
		ta->m = m;
		ta->s = client_sock;
		ta->r = remote_addr;

		rc = pthread_create(&connthread, NULL, mows_accept_request,
			ta);
		if (rc	!= 0) {
			free(ta);
			continue; /* XXX: break? */
		}

		pthread_detach(connthread); /* XXX: ??? */
	}

	return NULL;
}

int
mows_start(mows *m, const char *addr, const int port, int bg)
{
	struct sockaddr_in name;
	in_addr_t saddr;
	int one = 1;
	int ret = 0;

	/* init socket */
	m->s = socket(AF_INET, SOCK_STREAM, 0);
	if (m->s < 0) {
		ret = errno;
		goto fail_socket;
	}

	ret = setsockopt(m->s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (ret != 0) {
		ret = errno;
		goto fail;
	}

	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_port = htons(port);
	saddr = inet_addr(addr);
	if (saddr == INADDR_NONE) {
		ret = 1;
		goto fail;
	}
	name.sin_addr.s_addr = saddr;

	ret = bind(m->s, (struct sockaddr *)&name, sizeof(name));
	if (ret != 0) {
		ret = errno;
		goto fail;
	}

	ret = listen(m->s, 5);
	if (ret != 0) {
		ret = errno;
		goto fail;
	}

	m->stop = 0;
	m->bg = bg;
	if (m->bg) {
		/* run in background */
		ret = pthread_create(&m->bgthread, NULL, mows_work_loop, m);
		if (ret != 0) {
			goto fail;
		}
	} else {
		mows_work_loop(m);
	}

	return 0;

fail:
	close(m->s);
fail_socket:
	return ret;
}

void
mows_stop(mows *m)
{
	m->stop = 1;

	shutdown(m->s, 2);
	close(m->s);

	if (m->bg) {
		/* wait for background thread */
		pthread_join(m->bgthread, NULL);
	}
}

mows *
mows_alloc(mows_params *p)
{
	mows *m;

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

	return m;

fail_alloc:
	return NULL;
}

void
mows_free(mows *m)
{
	size_t i;

	/* free regexps */
	for (i=0; i<m->npages; i++) {
		if (!m->pages[i].is_page) {
			regfree(&m->pages[i].re);
		}
	}

	free(m->pages);
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

int
mows_add_page(mows *m, const char *p, mows_page_cb cb)
{
	struct mows_page_or_re *tmp;

	tmp = realloc(m->pages, (m->npages + 1)
		* sizeof(struct mows_page_or_re));
	if (!tmp) {
		return 0;
	}

	m->pages = tmp;
	/* append page URL and corresponding callback */
	m->pages[m->npages].is_page = 1;
	strncpy(m->pages[m->npages].url, p, HTTP_MAX_URL_SIZE);
	m->pages[m->npages].cb = cb;

	m->npages += 1;;

	return 1;
}

int
mows_add_re(mows *m, const char *re, mows_page_cb cb, char *err, size_t esize)
{
	struct mows_page_or_re *tmp;
	int res;
	regex_t r;

	res = regcomp(&r, re, REG_EXTENDED | REG_ICASE | REG_NOSUB);
	if (res != 0) {
		regerror(res, &r, err, esize);
		return 0;
	}

	tmp = realloc(m->pages, (m->npages + 1)
		* sizeof(struct mows_page_or_re));
	if (!tmp) {
		snprintf(err, esize, "Insufficient memory");
		return 0;
	}

	m->pages = tmp;
	/* append regex and corresponding callback */
	m->pages[m->npages].is_page = 0;
	m->pages[m->npages].re = r;
	m->pages[m->npages].cb = cb;

	m->npages += 1;;

	return 1;
}

void
mows_redirect302(const char *to, int s)
{
	char buf[HTTP_MAX_HEADER_SIZE];

	snprintf(buf, sizeof(buf),
		"HTTP/1.1 302 Found\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n"
		"Location: %s\r\n\r\n",
		to);
	mows_send_all(s, buf, strlen(buf));
}

/* request */
const char *
mows_req_url(mows_request *r)
{
	return r->url;
}

size_t
mows_req_nvars(mows_request *r)
{
	return r->nvars;
}

const char *
mows_req_var_name(mows_request *r, size_t i)
{
	return r->vars[i].name;
}

const char *
mows_req_var_val(mows_request *r, size_t i)
{
	return r->vars[i].val;
}

size_t
mows_req_nheaders(mows_request *r)
{
	return r->nheaders;
}

const char *
mows_req_header_name(mows_request *r, size_t i)
{
	return r->headers[i].name;
}

const char *
mows_req_header_val(mows_request *r, size_t i)
{
	return r->headers[i].val;
}

int
mows_req_method(mows_request *r)
{
	return r->method;
}
