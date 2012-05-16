
#include "config.h"

extern int trace_flag;

// byte bangers

// shift in a bite to the bottom of a 16 byte array, toss the last byte
static void shift_into_16_byte_array ( unsigned char *array, unsigned char b )
{
  int i;

  for ( i = AES_BLOCK_SIZE - 2 ; i > 0 ; i-- ) {
    array[i+1] = array[i];
  }
  array[0] = b;
}

// copy array
static void copy_16_byte_array ( unsigned char *targ, unsigned char *src )
{
  memcpy(targ,src,16);
}

// bind
void aes_pseudo_bind ( D_LFSR *d_lfsr, struct pgm_ctx_aes_struct_t *aes_ctx, AES_PSEUDO *aes_pseudo )
{
  unsigned char *targ,*src;
  int i;
  unsigned char b;

  // bind
  aes_pseudo->aes_pseudo_d_lfsr = d_lfsr;
  aes_pseudo->aes_pgm_ctx_aes   = aes_ctx;

  // initialize
  aes_ctx->crypto_register_init_flag = 1;
  aes_ctx->crypto_next_bit           = 0;

  // create 128 bits from d_lfsr into crypto_aes_register_a
  targ = aes_ctx->crypto_aes_register_a;
  for ( i = 0 ; i < AES_BLOCK_SIZE ; i++ ) {
    b = get_dual_lfsr_bits ( 8, d_lfsr );
    shift_into_16_byte_array(targ,b);
  }

  // encrypt a -> b

  targ = aes_ctx->crypto_aes_register_b;
  src = aes_ctx->crypto_aes_register_a;

  aes_encrypt( &aes_ctx->crypto_aes_ctx, targ, src);
}

// get bit
extern int get_bit ( unsigned char *array, int bitno );

#if 0
// show 16
static void show_16 ( char *what, unsigned char *array )
{
  unsigned int *x = (unsigned int *)array;

  printf("%s: 0x%08x 0x%08x 0x%08x 0x%08x\n",
	 what,
	 x[0],
	 x[1],
	 x[2],
	 x[3]);
}
#endif

// get one bit from AES_PSEUDO
unsigned int aes_pseudo_get_one_bit ( AES_PSEUDO *aes_pseudo )
{
  int res = 0;
  unsigned char *targ,*src;
  unsigned char b;

  // out of bits
  if ( aes_pseudo->aes_pgm_ctx_aes->crypto_next_bit > (AES_BLOCK_SIZE*8-1) ) {

    aes_pseudo->aes_pgm_ctx_aes->crypto_next_bit = 0;

    // copy register b -> a
    targ = aes_pseudo->aes_pgm_ctx_aes->crypto_aes_register_a;
    src  = aes_pseudo->aes_pgm_ctx_aes->crypto_aes_register_b;

    //show_16("reg A before copy",targ);
    //show_16("reg B before copy",src);

    copy_16_byte_array ( targ, src );

    //show_16("reg A after copy",targ);
    //show_16("reg B after copy",src);

    // get more bits
    b = get_dual_lfsr_bits ( 8, aes_pseudo->aes_pseudo_d_lfsr );

    //printf("d_lfsr returned 0x%02x\n",b&0xff);

    // shift bits into register a
    targ = aes_pseudo->aes_pgm_ctx_aes->crypto_aes_register_a;
    shift_into_16_byte_array ( targ, b);

    //show_16("reg A after shift",targ);

    // encrypt a with results into b
    targ = aes_pseudo->aes_pgm_ctx_aes->crypto_aes_register_b;
    src  = aes_pseudo->aes_pgm_ctx_aes->crypto_aes_register_a;
    aes_encrypt( &aes_pseudo->aes_pgm_ctx_aes->crypto_aes_ctx, targ, src);

    //show_16("reg A after encrypt",src);
    //show_16("reg B after encrypt",targ);
  }

  // Note: register b contains our bits

  src = aes_pseudo->aes_pgm_ctx_aes->crypto_aes_register_b;
  res = get_bit ( src, aes_pseudo->aes_pgm_ctx_aes->crypto_next_bit );
  aes_pseudo->aes_pgm_ctx_aes->crypto_next_bit += 1;

  // done
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

// get multi-bits from AES_PSEUDO
unsigned int aes_pseudo_get_multi_bit ( AES_PSEUDO *aes_pseudo, int cnt )
{
  unsigned int res = 0;
  int i;

  assert(cnt>0&&cnt<=sizeof(res)*8);

  // get as many bits as required
 retry:;
  for ( i = 0 ; i < cnt ; i++ ) {
    if ( aes_pseudo_get_one_bit ( aes_pseudo ) ) {
      res |= (1<<i);
    }
  }

  // reject all 0's for any request cnt > 4
  if ( cnt > 4 && 0 == (res & masks[cnt]) ) {
    res = 0;
    printf("%s: forced retry because res = 0x%08x, cnt = %d\n",
	   __FUNCTION__,
	   res,
	   cnt);
    goto retry;
  }
  // reject all 1's for any request cnt > 4
  if ( cnt > 4 && masks[cnt] == (res & masks[cnt]) ) {
    res = 0;
    printf("%s: forced retry because res = 0x%08x, cnt = %d\n",
	   __FUNCTION__,
	   res,
	   cnt);
    goto retry;
  }

  // trace for now
  if ( trace_flag > 1 ) {
    printf("%s: returning 0x%08x, cnt = %d\n",
	   __FUNCTION__,
	   res,
	   cnt );
  }

  // done
  return res;
}
