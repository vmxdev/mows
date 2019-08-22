#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mows.h"

static void
http_index(mows *m, mows_request *r, int s)
{
	char http[300], greeting[50];

	snprintf(greeting, sizeof(greeting), "<h1>Hello, world!</h1>");
	snprintf(http, sizeof(http),
		"HTTP/1.1 200 Ok\r\n"
		"Content-type: text/html\r\n"
		"Content-Length: %lu\r\n\r\n"
		"%s",
		strlen(greeting), greeting);

	mows_send_all(s, http, strlen(http));
}

int
main()
{
	mows *m;
	int rc;

	m = mows_alloc(NULL);
	if (!m) {
		fprintf(stderr, "Can't allocate memory\n");
		return EXIT_FAILURE;
	}

	mows_set_root(m, ".");
	mows_add_page(m, "/", &http_index);
	rc = mows_start(m, "127.0.0.1", 8080);
	if (rc != 0) {
		fprintf(stderr, "Error: %s\n", strerror(rc));
	}

	mows_free(m);

	return EXIT_SUCCESS;
}

