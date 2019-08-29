#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "mows.h"

static mows *m;

static void
http_index(mows *m, mows_request *r, int s)
{
	(void)m;
	(void)r;

	mows_redirect302("redirect.html", s);
}

void
ctrl_c_handler(int s)
{
	(void)s;
	mows_stop(m);
	mows_free(m);

	exit(EXIT_SUCCESS);
}

int
main()
{
	int rc;
	struct sigaction sa;

	/* setup Ctrl+C handler */
	memset(&sa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = ctrl_c_handler;
	sigaction(SIGINT, &sa, NULL);

	m = mows_alloc(NULL);
	if (!m) {
		fprintf(stderr, "Can't allocate memory\n");
		return EXIT_FAILURE;
	}

	mows_set_root(m, "./media/");

	if (!mows_add_page(m, "/", &http_index)) {
		fprintf(stderr, "Can't add page\n");
		return EXIT_FAILURE;
	}

	rc = mows_start(m, "127.0.0.1", 8081, 1);
	if (rc != 0) {
		fprintf(stderr, "Can't start server, error: %s\n",
			strerror(rc));
		return EXIT_FAILURE;
	}

	printf("Press ENTER or Ctrl+C to stop\n");
	getchar();

	mows_stop(m);

	mows_free(m);

	return EXIT_SUCCESS;
}

