#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "mows.h"

static mows *m;

static void
http_index(mows *m, mows_request *r, int s)
{
	char http[3000], vars[2500];
	size_t nvars, i;
	(void)m;

	snprintf(vars, sizeof(vars), "<h1>VARS:</h1><br />");

	nvars = mows_req_nvars(r);
	for (i=0; i<nvars; i++) {
		char var[100];
		snprintf(var, sizeof(var), "'%s': '%s'<br />\n",
			mows_req_var_name(r, i),
			mows_req_var_val(r, i));

		strcat(vars, var);
	}

	snprintf(http, sizeof(http),
		"HTTP/1.1 200 Ok\r\n"
		"Content-type: text/html\r\n"
		"Content-Length: %lu\r\n\r\n"
		"%s",
		strlen(vars), vars);

	mows_send_all(s, http, strlen(http));
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
	char errbuf[100];
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

	if (!mows_add_re(m, ".", &http_index, errbuf, sizeof(errbuf))) {
		fprintf(stderr, "Can't add regex: %s\n", errbuf);
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

