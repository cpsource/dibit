/** lfsr.c **/

// Note: The dual lfsr pseudo-random generators are a form of the shrinking generator
//
// see [1] http://en.wikipedia.org/wiki/LFSR
// see [2] http://en.wikipedia.org/wiki/Shrinking_generator
//
// for details
//
// from wikipedia [2]
//
//    Despite this simplicity, the shrinking generator has remained
//    remarkably resistant to cryptanalysis: there are currently no
//    known attacks better than exhaustive search when the feedback
//    polynomials are secret.
//

#include "config.h"

#if ! defined ( WIN32 )
#include <unistd.h>
#include <sys/time.h>
#else
#include <stdlib.h>
int time ( int * );
#endif

#include "lfsr.h"
#include "getkey.h"
#include "exp.h"

extern int trace_flag;

char poly[] = {
    44,3,2,0,-1
};

/*
 * some good polynomials from Handbook of
 * Applied Cryptography, page 161.
 */

// also taken from Xilinx LFSR V3.0 pdf

// Note: there are MAX_POLY_ARRAY of these
//       and that after init, poly_array[0..15]
//       points to each one.

static int p_array[] = {
  162,161,75,74,-1,
  //113,81,80,0,-1,
  114,14,0,-1,
  115,70,69,0,-1,
  116,19,17,1,-1,

  117,23,-1,
  118,7,0,-1,
  119,117,110,6,-1,
  164,163,151,150,-1,
  //120,17,-1,

  121,69,58,0,-1,
  122,1,-1,
  166,165,128,127,-1,
  //123,36,-1,
  124,107,106,0,-1,

  125,36,35,0,-1,
  168,166,153,151,-1,
  //126,0,-1,
  127,28,26,1,-1,
  128,4,-1,

  -1
};

int *poly_array[MAX_POLY_ARRAY];

/* setup 'poly_array' */
static void new_poly_array()
{
  int i;
  int *x;

  for ( x = p_array, i = 0 ; i < MAX_POLY_ARRAY ; i++ ) {
    poly_array[i] = x;

    /* get next x */
    while ( *x != -1 ) {
      x++;
    }
    x++;
  }
}

/* initialize the lfsr module */
void lfsr_init( PGM_CTX *pgm_ctx )
{
  new_poly_array();

  memset(pgm_ctx->poly_array_used,0,sizeof(pgm_ctx->poly_array_used));
}

#define get_bit(array,bitno) ({				\
      int idx = bitno / (sizeof(unsigned int)*8);	\
      int off = bitno % (sizeof(unsigned int)*8);	\
      ((unsigned int *)array) [ idx ] & (1<<off) ? 1 : 0; \
    })

#define set_bit(array,bitno,v) ({ \
      int idx = bitno / (sizeof(unsigned int)*8);	\
      int off = bitno % (sizeof(unsigned int)*8);	\
      if ( v ) {					\
	((unsigned int *)array) [ idx ] |= (1<<off);	\
      } else {						\
	((unsigned int *)array) [ idx ] &= ~(1<<off);	\
      }							\
    })

static void shift_left ( unsigned int *array /* , int max */ )
{
  unsigned int m [ BIG_SEED_MAX / 4 ];
  int i;

  for ( i = (BIG_SEED_MAX/4)-1 ; i > 0 ; i-- ) {
    m[i] = array[i] << 1;
    if ( array[i-1] & 0x80000000 ) {
      // carry
      m[i] |= 1;
    }
  }
  m[0] = array[0] << 1;
  //set_bit(m,max,0);
  memcpy(array,m,BIG_SEED_MAX);
}

// clock a poly array once
static int lfsr_clock_once ( BIG_SEED *big_seed, int *poly_array )
{
  int m;
  int bit = 0;
  int i;
  int res;

  // get taps
  for ( i = 0 ; (m=poly_array[i]) != -1 ; i++ ) {
    bit ^= get_bit(big_seed->bigSeed,m);
  }
  // shift left
  shift_left( (unsigned int *)big_seed->bigSeed /* ,poly_array[0]+1 */);

  // or in result
  big_seed->bigSeed[0] |= (bit & 1);

  // get highest order bit as result
  res = get_bit(big_seed->bigSeed,poly_array[0]);

  // done, return result
  return res;
}

/* get dual_lfsr_bits */
//
// Note: we shift two polys, if the first one returns true,
//       we 'or' in the second and count it as a bit,
//       else we continue.
//
unsigned int get_dual_lfsr_bits ( int num_bits, D_LFSR_PTR x )
{
  unsigned int res = 0;
  int i   = 0;

  while ( num_bits > 0 ) {
    int tmp; 
    int tmp1;

    /* clock both sr's */
    tmp  = lfsr_clock_once(&x->bs_A,x->poly_A);
    tmp1 = lfsr_clock_once(&x->bs_B,x->poly_B);

    if ( tmp ) {
      /* printf("bit = %d\n",tmp1); */
      res |= ( tmp1 << i );
    } else {
      /* no bit generated, try again */
      continue;
    }

    num_bits--;
    i++;
  }

#if 0
  if ( trace_flag ) printf("%s: returning 0x%08x\n",
			   __FUNCTION__,
			   res);
#endif

  return res;
}

/* init_dual_lfsr_from_key */
void init_dual_lfsr_from_key ( PGM_CTX *pgm_ctx,
			       D_LFSR *x,               /* output structure      */
			       KEYBUF_3_ITERATOR *kb3_i /* key bits              */
			       )
{
  aDat a;  /* BIT_MAX number of bits in size */
  int cnt; /* number of bits stored here     */
  int idx; /* index into bigSeed             */
  int poly_idx;

  /* zero */
  memset( x, 0, sizeof(D_LFSR) );

  // get two uniq polys
  while ( 1 ) {
    poly_idx = getNKeyBits_3_iterator ( pgm_ctx, 4, kb3_i );
    if ( pgm_ctx->poly_array_used [ poly_idx ] ) {
      continue;
    }
    break;
  }
  pgm_ctx->poly_array_used [ poly_idx ] = 1;
  if ( trace_flag > 1 ) printf("%s: selecting poly %d\n",__FUNCTION__,poly_idx);
  /* store polynomial ptrs for later */
  x->poly_A = poly_array [ poly_idx ];

  while ( 1 ) {
    poly_idx = getNKeyBits_3_iterator ( pgm_ctx, 4, kb3_i );
    if ( pgm_ctx->poly_array_used [ poly_idx ] ) {
      continue;
    }
    break;
  }
  pgm_ctx->poly_array_used [ poly_idx ] = 1;
  if ( trace_flag > 1 ) printf("%s: selecting poly %d\n",__FUNCTION__,poly_idx);
  /* store polynomial ptrs for later */
  x->poly_B = poly_array [ poly_idx ];

  /* initialize bs_A from key */
  cnt = x->poly_A[0];
  idx = 0;
  while ( cnt > 0 ) {
    a = getNKeyBits_3_iterator ( pgm_ctx, 8 , kb3_i );
    x->bs_A.bigSeed[idx++] = a;
    cnt -= 8;
  }

  /* initialize bs_B from key */
  cnt = x->poly_B[0];
  idx = 0;
  while ( cnt > 0 ) {
    a = getNKeyBits_3_iterator ( pgm_ctx, 8 , kb3_i );
    x->bs_B.bigSeed[idx++] = a;
    cnt -= 8;
  }

  /* return to caller */
}

#if defined(CP_TEST)

// see http://en.wikipedia.org/wiki/LFSR
// see http://en.wikipedia.org/wiki/Shrinking_generator

#if 0
If all works well, you will get this sample output
[root@localhost nextprime]# ./lfsr_tst
period = 65535
period = 65536 - 000000000000000000000000000000000002ce0b 0000000000000000000000000000000000006b3d
period = 131072 - 0000000000000000000000000000000000022d59 0000000000000000000000000000000000006b3d
period = 196608 - 0000000000000000000000000000000000047279 0000000000000000000000000000000000006b3d
period = 262144 - 000000000000000000000000000000000005289b 0000000000000000000000000000000000006b3d
period = 327680 - 000000000000000000000000000000000001418a 0000000000000000000000000000000000006b3d
period = 393216 - 0000000000000000000000000000000000003344 0000000000000000000000000000000000006b3d
period = 458752 - 0000000000000000000000000000000000067190 0000000000000000000000000000000000006b3d
period = 524287 - 0000000000000000000000000000000000006b3d 0000000000000000000000000000000000006b3d
bytes_needed(128) = 17 bytes
#endif // 0

#include <stdio.h>
#include <string.h>

// our byte size
#define B 20

char poly1[] = {
    113,81,80,0,-1
};

#define get_bit(array,bitno) ({				\
      int idx = bitno / (sizeof(unsigned int)*8);	\
      int off = bitno % (sizeof(unsigned int)*8);	\
      ((unsigned int *)array) [ idx ] & (1<<off) ? 1 : 0; \
    })

#define set_bit(array,bitno,v) ({ \
      int idx = bitno / (sizeof(unsigned int)*8);	\
      int off = bitno % (sizeof(unsigned int)*8);	\
      if ( v ) {					\
	((unsigned int *)array) [ idx ] |= (1<<off);	\
      } else {						\
	((unsigned int *)array) [ idx ] &= ~(1<<off);	\
      }							\
    })

void shift_left ( unsigned int *array, int max )
{
  unsigned int m [ B/4 ];
  int i;

  for ( i = (B/4)-1 ; i > 0 ; i-- ) {
    m[i] = array[i] << 1;
    if ( array[i-1] & 0x80000000 ) {
      // carry
      m[i] |= 1;
    }
  }
  m[0] = array[0] << 1;
  set_bit(m,max,0);
  memcpy(array,m,B);
}

unsigned short lfsr = 0xACE1u;
int bit;
unsigned long long period = 0;

char f0[ B ];
char f [ B ];

void show_f ( char *m )
{
  int i;
  for ( i = B-1 ; i >= 0 ; i-- ) {
    printf("%02x",m[i] & 0xff );
  }
}

int clog2 ( unsigned int *m )
{
  int res = 0;
  int i;

  for ( i = 0 ; i < B*8 ; i++ ) {
    if ( get_bit(m,i) ) {
      res = i;
    }
  }

  return res;
}

int bytes_needed ( unsigned int *m )
{
  int l2 = clog2(m) + 1;
  int b;

  b = l2 / 8;
  if ( l2 % 8 ) {
    b += 1;
  }

  return b;
}

int main()
{
  int i;

  do {
    /* taps: 16 14 13 11; feedback polynomial: x^16 + x^14 + x^13 + x^11 + 1 */
    bit  = ((lfsr >> 0) ^ (lfsr >> 2) ^ (lfsr >> 3) ^ (lfsr >> 5) ) & 1;
    lfsr =  (lfsr >> 1) | (bit << 15);
    ++period;
  } while(lfsr != 0xACE1u);

  printf("period = %d\n",(int)period);

  // run 18,17,16,13
  memset(f,0,B);
  for ( i = 0 ; i <= 18 ; i++ ) {
    set_bit ( f, i, rand() & 1 );
  }
  memcpy(f0,f,B);
  period = 0;

  do {
    // get taps
    bit = get_bit(f,18) ^ get_bit(f,17) ^ get_bit(f,16) ^ get_bit(f,13);
    // shift left
    shift_left((unsigned int *)f,19);
    // or in result
    f[0] |= (bit & 1);

#if 0
    // grab data
    if ( get_bit((unsigned int *)f,113) ) {
      printf("t");
    } else {
      printf("f");
    }
#endif

    period += 1;

    if ( !(period & 0xffff) ) {
      printf("period = %lld - ",period);
      show_f ( f ); printf(" ");
      show_f ( f0 ); printf("\n");
    }

  } while ( 0 != memcmp(f0,f,B) );

  printf("period = %lld - ",period);
  show_f ( f ); printf(" ");
  show_f ( f0 ); printf("\n");

  // log2 tests
  memset(f,0,B);
  set_bit(f,128,1);
  printf("bytes_needed(128) = %d bytes\n",
	 bytes_needed((unsigned int *)f));

  // done
  return 0;
}
#endif
