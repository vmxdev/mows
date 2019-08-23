#ifndef mows_h_included
#define mows_h_included

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum MOWS_PARAM
{
	MOWS_PARAM_NTHREADS
} MOWS_PARAM;

typedef struct mows_params mows_params;
typedef struct mows mows;
typedef struct mows_request mows_request;
typedef struct mows_response mows_response;

typedef void (*mows_page_cb) (mows *m, mows_request *r, int s);

/* params */
mows_params *mows_params_new(void);
void mows_params_free(mows_params *p);

void mows_params_set(mows_params *p, MOWS_PARAM param, uint64_t val);

/* server */
mows *mows_alloc(mows_params *p);
int   mows_start(mows *m, const char *addr, const int port);

void  mows_free(mows *m);

int mows_set_root(mows *m, const char *dir);
int mows_add_page(mows *m, const char *p, mows_page_cb cb);
int mows_add_re(mows *m, const char *re, mows_page_cb cb, char *err,
	size_t esize);

int mows_send_all(int sock, char *buffer, size_t len);

/* request */
const char *mows_req_url(mows_request *r);

#ifdef __cplusplus
}
#endif

#endif

