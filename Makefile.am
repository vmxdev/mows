bin_PROGRAMS = example_hello example_redirect

# Create a statically linked example
example_hello_SOURCES = example_hello.c
example_hello_LDADD = libmows.la
example_hello_LDFLAGS = -static

example_redirect_SOURCES = example_redirect.c
example_redirect_LDADD = libmows.la
example_redirect_LDFLAGS = -static

lib_LTLIBRARIES = libmows.la
libmows_la_SOURCES = http_parser.c mows.c


ACLOCAL_AMFLAGS = -I m4
