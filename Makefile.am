bin_PROGRAMS = example_hello example_redirect \
	example_vars example_headers

# Create a statically linked example
example_hello_SOURCES = example_hello.c
example_hello_LDADD = libmows.la
example_hello_LDFLAGS = -static

example_redirect_SOURCES = example_redirect.c
example_redirect_LDADD = libmows.la
example_redirect_LDFLAGS = -static

example_vars_SOURCES = example_vars.c
example_vars_LDADD = libmows.la
example_vars_LDFLAGS = -static

example_headers_SOURCES = example_headers.c
example_headers_LDADD = libmows.la
example_headers_LDFLAGS = -static

lib_LTLIBRARIES = libmows.la
libmows_la_SOURCES = http_parser.c mows.c


ACLOCAL_AMFLAGS = -I m4
