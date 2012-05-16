// take advantage of linux /dev/urandom
// see also http://en.wikipedia.org/wiki//dev/random

#include "config.h"

extern int trace_flag;

// init
void urandom_pseudo_init ( PGM_CTX *pgm_ctx )
{
  if ( !pgm_ctx->urandom_init_ok ) {
    pgm_ctx->urandom_fd = open ( "/dev/urandom", O_RDONLY );
    if ( pgm_ctx->urandom_fd < 0 ) {
      printf("%s: Error, could not open </dev/urandom>'\n",__FUNCTION__);
      exit(0);
    } else {
      // get some bytes
      urandom_randbytes(pgm_ctx, pgm_ctx->urandom_data,URANDOM_PSEUDO_CHUNK);
      // set index to next bit out
      pgm_ctx->urandom_next_bit = 0;
      // set init flag
      pgm_ctx->urandom_init_ok = 1;
    }
  }
}

// get some bytes
void urandom_randbytes(PGM_CTX *pgm_ctx, char *retbuf, size_t nbytes)
{
  rw(read,pgm_ctx->urandom_fd,retbuf,nbytes);
}

// external reference - get bit
int get_bit ( unsigned char *array, int bitno );

// get one bit from urandom_pseudo
unsigned int urandom_pseudo_get_one_bit ( PGM_CTX *pgm_ctx )
{
  int res = 0;

  if ( pgm_ctx->urandom_next_bit >= URANDOM_PSEUDO_CHUNK*8 ) {
    pgm_ctx->urandom_next_bit = 0;
    urandom_randbytes(pgm_ctx,pgm_ctx->urandom_data,URANDOM_PSEUDO_CHUNK);
  }

  res = get_bit ( pgm_ctx->urandom_data, pgm_ctx->urandom_next_bit );

  pgm_ctx->urandom_next_bit += 1;
  
  return res;
}

// a useful table to judge the worthiness of a pseudo-random number
static unsigned int masks [ 33 ] = {
  0,
  0x1,0x3,0x7,0xf,
  0x1f,0x3f,0x7f,0xff,
  0x1ff,0x3ff,0x7ff,0xfff,
  0x1fff,0x3fff,0x7fff,0xffff,

  0x1ffff,0x3ffff,0x7ffff,0xfffff,
  0x1fffff,0x3fffff,0x7fffff,0xffffff,
  0x1ffffff,0x3ffffff,0x7ffffff,0xfffffff,
  0x1fffffff,0x3fffffff,0x7fffffff,0xffffffff };

// get multi-bits from urandom_pseudo
unsigned int urandom_pseudo_get_multi_bit ( PGM_CTX *pgm_ctx, int cnt )
{
  unsigned int res = 0;
  int i;

  assert(cnt>0&&cnt<=sizeof(res)*8);

 retry:;

  if ( !(cnt%8) ) {
    // optimize
    urandom_randbytes(pgm_ctx, (char *)&res, cnt/8);
  } else {
    // slog through
    for ( i = 0 ; i < cnt ; i++ ) {
      if ( urandom_pseudo_get_one_bit(pgm_ctx) ) {
	res |= (1<<i);
      }
    }
  }

  // reject all 0's for any request cnt > 4
  if ( cnt > 4 && 0 == (res & masks[cnt]) ) {
    res = 0;
    if ( trace_flag > 1 )
      printf("%s: forced retry because res = 0x%08x, cnt = %d\n",
	     __FUNCTION__,
	     res,
	     cnt);
    goto retry;
  }
  // reject all 1's for any request cnt > 4
  if ( cnt > 4 && masks[cnt] == (res & masks[cnt]) ) {
    res = 0;
    if ( trace_flag > 1 )
      printf("%s: forced retry because res = 0x%08x, cnt = %d\n",
	     __FUNCTION__,
	     res,
	     cnt);
    goto retry;
  }

  return res;
}
