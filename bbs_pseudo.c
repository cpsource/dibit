#include <alloca.h>

#include "config.h"
#include "/usr/local/include/gmp.h"

extern int trace_flag;

// create an mpz_t from a char array of size array_cnt
static void bbs_pseudo_cvt_bytes_to_mpz ( unsigned char *array, int array_cnt , mpz_t result )
{
  char *v_buf;
  char *c;
  int i;

  c = v_buf = alloca ( array_cnt*2 + 1 );
  v_buf [ array_cnt*2 ] = 0;

  for ( i = array_cnt - 1 ; i >= 0 ; i--, c += 2 ) {
    sprintf(c,"%02x",array[i]&0xff);
  }

#if 0 && defined(CP_TEST)
  printf("%s\n",v_buf);
#endif

  mpz_set_str(result,v_buf,16);
}

// get next prime where p mod 4 = 3
static void bbs_pseudo_next_prime ( mpz_t arg )
{
  mpz_t r;
  mpz_t mod;

  mpz_init(r);
  mpz_init(mod);

  mpz_set(r,arg);

 loop:;
  mpz_nextprime(r,r);
  mpz_mod_ui(mod,r,4);

  if ( 0 != mpz_cmp_ui(mod,3) ) {
#if 0 && defined(CP_TEST)
    printf("%s: redo\n",__FUNCTION__);
#endif
    goto loop;
  }

  mpz_set(arg,r);

  mpz_clear(r);
  mpz_clear(mod);
}

// init
void bbs_pseudo_init ( PGM_CTX *pgm_ctx )
{
  RNDBBS *bbs;
  mpz_t p,q;
  KEYBUF_128 *kb_128;

  // pick up handy ptr
  bbs = &pgm_ctx->rndbbs;

  // init pgm_ctx
  mpz_init(bbs->blumint);
  mpz_init(bbs->x);
  bbs->key_bitlen  = 0;
  bbs->improved    = 1;
  bbs->xor_urandom = 0;

  // init local vars
  mpz_init(p);
  mpz_init(q);

  // get p, use key_four as starting point
  kb_128 = &pgm_ctx->dibit_kb3_i.kb->key_four;
  bbs_pseudo_cvt_bytes_to_mpz ( kb_128->k, KEYBUF_128_SIZE, p);
  bbs_pseudo_next_prime ( p );

  // encrypt key_four as we've used it up
  {
    unsigned char *kc;
    int i;

    // pick up ptr to buffer
    kc = kb_128->k;
    // make big
    *kc |= 0xc0;
    // make odd
    kc [ KEYBUF_128_SIZE -1 ] |= 0x1;

    for ( i = 0 ; i < KEYBUF_128_SIZE/AES_BLOCK_SIZE ; i++, kc += AES_BLOCK_SIZE ) {
      aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		   pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		   kc);
      memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);
    }
  }

  // get q
  mpz_set(q,p);
  bbs_pseudo_next_prime ( q );

  // calculate blumint
  mpz_mul(bbs->blumint,p,q);
  bbs->key_bitlen = mpz_sizeinbase(bbs->blumint, 2);

  // get bbs->x
  {
    mpz_t tmpgcd;
    unsigned char m[4];

    mpz_init(tmpgcd);

    m[0] = getNKeyBits_3_iterator ( pgm_ctx, 8, &pgm_ctx->dibit_kb3_i );
    m[1] = getNKeyBits_3_iterator ( pgm_ctx, 8, &pgm_ctx->dibit_kb3_i );
    m[2] = getNKeyBits_3_iterator ( pgm_ctx, 8, &pgm_ctx->dibit_kb3_i );
    m[3] = getNKeyBits_3_iterator ( pgm_ctx, 8, &pgm_ctx->dibit_kb3_i );

    // get trial x
    bbs_pseudo_cvt_bytes_to_mpz ( m, 4, bbs->x );

    // make sure 'x' is good

    while ( 1 ) {
      mpz_gcd(tmpgcd, bbs->blumint, bbs->x);
      if (mpz_cmp_ui(tmpgcd, 1) != 0)
	{
	  // here, not so good, try again
	  mpz_add_ui(bbs->x,bbs->x,1);
	  continue;
	}
      break;
    }

    // finally, calculate x[0]

    /* x[0] = x^2 (mod n) */
    mpz_powm_ui(bbs->x, bbs->x, 2, bbs->blumint);

    // tidy up
    mpz_clear(tmpgcd);
  }

  // display if necessary
  if ( trace_flag > 1 ) {
    printf("\n%s: bbs->key_bitlen = %d\n",
	   __FUNCTION__,
	   bbs->key_bitlen);
    gmp_printf ("p      : %Zx\n", p);
    gmp_printf ("q      : %Zx\n", q);
    gmp_printf ("x[0]   : %Zx\n", bbs->x);
    gmp_printf ("blumint: %Zx\n", bbs->blumint);
    printf("\n");
  }

  // cleanup
  mpz_clear(p);
  mpz_clear(q);

  // done
}

// get some bytes (taken from gmpbbs.c)
void rndbbs_randbytes(PGM_CTX *pgm_ctx, char *retbuf, size_t nbytes)
#define FUNC_NAME "rndbbs_randbytes"
{
  char *urandom_buffer = NULL;
  RNDBBS *bbs;

  // pick up handy ptr
  bbs = &pgm_ctx->rndbbs;

  if ( bbs->xor_urandom )
    {
      if ( (urandom_buffer = (char *) malloc(nbytes)) == NULL)
	{
	  perror(FUNC_NAME ": malloc");
	  return;
	}

      {
	int i;
	int j;
	unsigned int r;

	r = nrand48(pgm_ctx->xsubi);
	for ( j = 0, i = 0 ; i < nbytes ; i++ ) {
	  if ( j > 3 ) {
	    j = 0;
	    r = nrand48(pgm_ctx->xsubi);
	  }
	  urandom_buffer [ i ] = (unsigned char)r;
	  r >>= 8;
	  j += 1;
	}
      }

#if 0
      if ( _urandread(urandom_buffer, nbytes) != nbytes )
	{
	  perror(FUNC_NAME ": _urandread: continuting...");
	  bbs->xor_urandom = 0;
	}
#endif
    }

  memset(retbuf, 0, nbytes);

  if (!bbs->improved)
    {
      /* basic implementation without improvements (only keep parity) */
      {
	int i;
	for (i=0;i<nbytes;i++)
	  {
	    int j;

	    /* we keep the parity (least significant bit) of each x_n */
	    for (j=7;j>=0;j--)
	      {
		/* x[n+1] = x[n]^2 (mod blumint) */
		mpz_powm_ui(bbs->x, bbs->x, 2, bbs->blumint);

		/* mpz_fdiv_ui(bbs->x, 2) == mpz_tstbit(bbs->x, 0) */
		retbuf[i] |= (mpz_tstbit(bbs->x, 0) << j);
	      }
	    if (bbs->xor_urandom)
	      retbuf[i] ^= urandom_buffer[i];
	  }
	if ( urandom_buffer != NULL )
	  free(urandom_buffer);
	return;
      }
    }
  else
    {
      /* improved implementation (keep log2(log2(blumint)) bits of x[i]) */
      unsigned int loglogblum = log(1.0*bbs->key_bitlen)/log(2.0);

      unsigned int byte=0, bit=0, i;

      for (;;)
	{
	  //printf("%s: calculating x[n+1], loglogblum = %d\n",
	  //__FUNCTION__,loglogblum);
	  
	  /* x[n+1] = x[n]^2 (mod blumint) */
	  mpz_powm_ui(bbs->x, bbs->x, 2, bbs->blumint);

	  for (i=0;i<loglogblum;i++)
	    {
	      if (byte == nbytes)
		{
		  if ( urandom_buffer != NULL )
		    free(urandom_buffer);
		  return;
		}

	      /* get the ith bit of x */
	      retbuf[byte] |= (mpz_tstbit(bbs->x, i) << (7-bit) );

	      if (bit == 7)
		{
		  if (bbs->xor_urandom)
		    retbuf[byte] ^= urandom_buffer[byte];
		  byte++;
		  bit=0;
		}
	      else
		{
		  bit++;
		}
	    }
	}
    }
}

// get bit
int get_bit ( unsigned char *array, int bitno );

// get one bit from BBS_PSEUDO
unsigned int bbs_pseudo_get_one_bit ( PGM_CTX *pgm_ctx )
{
  int res = 0;

  // have we loaded up our cache ???
  if ( !pgm_ctx->rndbbs_init_ok || pgm_ctx->rndbbs_idx >= RNDBBS_KEY_CNT*8 ) {
    // no, do so now
    rndbbs_randbytes(pgm_ctx, pgm_ctx->rndbbs_data, RNDBBS_KEY_CNT);
    // init cache ctrs, flags, etc
    pgm_ctx->rndbbs_init_ok = 1;
    pgm_ctx->rndbbs_idx     = 0;
  }

  res = get_bit ( pgm_ctx->rndbbs_data, pgm_ctx->rndbbs_idx );
  pgm_ctx->rndbbs_idx += 1;
  
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

// get multi-bits from BBS_PSEUDO
unsigned int bbs_pseudo_get_multi_bit ( PGM_CTX *pgm_ctx, int cnt )
{
  unsigned int res = 0;
  int i;

  assert(cnt>0&&cnt<=sizeof(res)*8);

 retry:;
  for ( i = 0 ; i < cnt ; i++ ) {
    if ( bbs_pseudo_get_one_bit(pgm_ctx) ) {
      res |= (1<<i);
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

  //printf("%s: returning res = 0x%08x\n",__FUNCTION__,res);

  return res;
}

#if defined(CP_TEST)
int main( int argc, char *argv[] )
{
  mpz_t r;
  unsigned char key [ 128 ];
  int i;

  srand(atoi(argv[1]));

  mpz_init(r);

  for ( i = 0 ; i < 128 ; i++ ) {
    key[i] = rand();
  }

  bbs_pseudo_cvt_bytes_to_mpz ( key, 128, r );

  gmp_printf ("r: %Zx\n", r);
  bbs_pseudo_next_prime ( r );
  gmp_printf ("p: %Zx\n", r);

  return 0;
}
#endif // CP_TEST
