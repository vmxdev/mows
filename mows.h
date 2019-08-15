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

/* params */
mows_params *mows_params_new(void);
void mows_params_free(mows_params *p);

void mows_params_set(mows_params *p, MOWS_PARAM param, uint64_t val);

/* server */
mows *mows_new(mows_params *p, const char *addr, const int port);
void  mows_free(mows *m);

#ifdef __cplusplus
}
#endif

#endif

