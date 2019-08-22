#include <stdlib.h>

#include "mows.h"

int
main()
{
	mows *m;

	m = mows_new(NULL, "127.0.0.1", 8080);

	mows_set_root(m, ".");
	mows_start(m);

	mows_free(m);
	return EXIT_SUCCESS;
}

