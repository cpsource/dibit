#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "config.h"

#include "pgm_ctx.h"

// create new program context structure
PGM_CTX *pgm_ctx_new ( void )
{
  PGM_CTX *res = (PGM_CTX *)malloc(sizeof(PGM_CTX));
  assert(res!=NULL);
  memset(res,0,sizeof(PGM_CTX));

  // key_file.c
  res->key_file_prev_offset = -1;
  res->key_file_fd = -1;

  return res;
}
