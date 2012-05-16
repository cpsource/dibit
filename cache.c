// speed up access into bit array
//
// Note: benchmarks show this speeds up encoding by 33% for
//       a tradeoff in complexity
//

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <search.h>

#include "config.h"
#include "cache.h"

//#define CP_TRACE

#define CE_MAP 1024

// easy macros
#define IS_END(ce) ( (char *)ce == (char *)&ctx->ce_q )
#define IS_FIRST(ce) ( (char *)ce->q.q_back == (char *)&ctx->ce_q )
#define IS_LAST(ce) ( (char *)ce->q.q_forw == (char *)&ctx->ce_q )

// a queue of CE's

// create an initial ctx
CTX *cache_ctx_new ( void )
{
  CTX *ctx = (CTX *)malloc(sizeof(CTX));
  assert(ctx!=NULL);

  ctx->ce_q.q_forw = &ctx->ce_q;
  ctx->ce_q.q_back = &ctx->ce_q;

  return ctx;
}

// init ces
void cache_init_ces ( CTX *ctx, int bit_max )
{
  CE *ce;
  int offset = 0;

  // free anybody on ce_q
  while ( (unsigned char *)ctx->ce_q.q_forw != (unsigned char *)&ctx->ce_q ) {
    ce = (CE *)ctx->ce_q.q_forw;
    remque(ce);
    free(ce);
  }

  // init queue
  ctx->ce_q.q_forw = &ctx->ce_q;
  ctx->ce_q.q_back = &ctx->ce_q;

  // create a CE for each block of data presented
  while ( 1 ) {
    if ( offset > bit_max ) {
      break;
    } else {

      ce = (CE *)malloc ( sizeof(CE) );
      assert(ce!=NULL);

      ce->bit_offset = offset;
      ce->off        = offset / 4;
      ce->bit        = 0;

      insque ( ce, ctx->ce_q.q_back );
    }

    // onward
    offset += CE_MAP;
  }
}

// return TRUE if ce in range
static int ce_in_range ( CTX *ctx, CE *ce , int bit_offset )
{
  CE *nxt;

  if ( IS_LAST(ce) ) return 1;

  if ( IS_FIRST(ce) ) {
    nxt = (CE *)ce->q.q_forw;
    if ( bit_offset < nxt->bit_offset ) return 1;
    return 0;
  }

  // neither first nor last
  nxt = (CE *)ce->q.q_forw;
  if ( bit_offset >= ce->bit_offset &&
       bit_offset < nxt->bit_offset ) return 1;

  return 0;
}


#if defined(CP_TRACE)
static void show_ce( CE *ce)
{
  printf("%s: entry, ce = %p\n",
	 __FUNCTION__,ce);
  printf("  bit_offset = %d\n",ce->bit_offset);
  printf("  off        = %d\n",ce->off);
  printf("  bit        = %d\n",ce->bit);
}
#endif // CP_TRACE

static int do_local_match ( CTX *ctx, CE *ce, unsigned char *array, int bit_offset, int rbit_flag )
{
  int ret;
  int off;
  int bit;

  off         = ce->off;
  bit         = ce->bit;
  bit_offset -= ce->bit_offset;

  // walk forward until we find our guy
  while ( 1 ) {
    int bit_mask;
    int dibit_mask;
      
    bit_mask   = 1<<(bit*2);
    dibit_mask = 1<<(bit*2 + 1);

    if ( !(array[off]&dibit_mask) ) {
      // count
      if ( bit_offset == 0 ) {
	// found
	if ( rbit_flag ) {
	  ret = off * 4 + bit;
	} else {
	  ret = array[off]&bit_mask ? 1 : 0;
	}
	array[off] |= dibit_mask;

#if defined(CP_TRACE)
	printf("%s: found bit, array[%d] = 0x%02x, bit_mask = 0x%02x, ret = %d\n",
	       __FUNCTION__,
	       off,array[off]&0xff,bit_mask,ret);
#endif

	break;
      }
      bit_offset -= 1;
    }
    bit += 1;
    if ( bit > 3 ) {
      bit = 0;
      off += 1;
    }
  } // while

  // decrement by 1 everyone after this CE
  ce = (CE *)ce->q.q_forw;
  while ( !IS_END(ce) ) {
    CE *nxt = (CE *)ce->q.q_forw;
    if ( ce->bit_offset ) {
      ce->bit_offset -= 1;
      if ( ce->bit_offset < 0 ) {
	remque(ce);
	free(ce);
      }
    }
    // onward
    ce = nxt;
  }
  return ret;
}

// find idx and bit for a given bit_offset
// return value
int cache_find_dibit ( CTX *ctx, unsigned char *array, int bit_offset )
{
  CE *ce;
  int ret;

#if defined(CP_TRACE)
  printf("%s: entry, bit_offset = %d (0x%08x)\n",
	 __FUNCTION__,
	 bit_offset, bit_offset);
#endif

  ce = (CE *)ctx->ce_q.q_forw;
  while ( !IS_END(ce) ) {

    CE *nxt = (CE *)ce->q.q_forw; // save next ce as current one may goa

    if ( ce_in_range(ctx,ce,bit_offset) ) {
      // match the bits
      ret = do_local_match ( ctx, ce, array, bit_offset, 0 );
      // done
      return ret;
    }
    ce = nxt;
  } // while

#if defined(CP_TRACE)
  printf("%s: Fatal Internal Error, after while\n",__FUNCTION__);
  exit(0);
#endif

  return 0;
}

#if defined(USE_RBIT_TEST)

// find the bit number in rbit file
//
// Note: This returns a dibit offset, NOT the bit offset
//
int cache_find_rbit ( CTX *ctx, unsigned char *array, int bit_offset )
{
  CE *ce;
  int ret;

#if defined(CP_TRACE)
  printf("%s: entry, bit_offset = %d\n",
	 __FUNCTION__,
	 bit_offset);
#endif

  ce = (CE *)ctx->ce_q.q_forw;
  while ( !IS_END(ce) ) {

    CE *nxt = (CE *)ce->q.q_forw; // save next ce as current one may goa

    if ( ce_in_range(ctx,ce,bit_offset) ) {
      // match the bits
      ret = do_local_match ( ctx, ce, array, bit_offset, 1 );
      // done
      return ret;
    }
    ce = nxt;
  } // while

#if defined(CP_TRACE)
  printf("%s: Fatal Internal Error, after while\n",__FUNCTION__);
  exit(0);
#endif

  return 0;
}

#endif
