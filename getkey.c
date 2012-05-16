/* #define CPTRACE 1 */

/** getkey.c **/

#include "config.h"

#include "lfsr.h"
#include "key_file.h"

#include "getkey.h"

#if defined(USE_SHA1)
#include "sha1.h"
#endif

#if defined(USE_LIBGCRYPT)
#include <gcrypt.h>
#endif

extern int trace_flag;

/* show bits_used */
void show_bits_used ( KEYBUF_3_PTR kp_3 )
{
  printf("bits used = %d\n",
	 kp_3->bits_used);
}

#if 0
/* get number of unused bits */
static int unUsedBits ( KEYBUF_PTR kp )
{
  int res;
	
  if ( kp->keyMax * 8 > kp->usedBits ) {
    res = kp->keyMax * 8 - kp->usedBits;
  } else {
    res = 0;
  }

#if 0
  printf("unUsedBits: keyMax*8 = %d, usedBits = %d\n",
	 kp->keyMax*8,
	 kp->usedBits);
#endif /* 0 */

  return res;
}
#endif // 0

/* return true if we did wrap */
#if 1
#define did_wrap_true(kp) (0 == kp->bit && 0 == kp->idx)
#else
static int did_wrap_true ( KEYBUF_PTR kp )
{
  if ( 0 == kp->bit && 0 == kp->idx ) {
    return 1;
  }
  return 0;
}
#endif

#if 0
/* get next key bit from kp */
static int nextKeyBit ( KEYBUF_PTR kp )
{
  int res;

  /* get the bit */
  res = 1 & (((1<<kp->bit) & kp->k[kp->idx]) >> kp->bit);

  /* update indexes to next bit, wrap if necessary */
  if ( ++kp->bit > 7 ) {
    kp->bit = 0;
    if ( ++kp->idx >= kp->keyMax ) {
      kp->idx = 0;
    }
  }

  /* keep track of the number of bits we have used */
  kp->usedBits++;

  /* return bit to caller */
  return res;
}
#endif

#if 0
/* get n key bits */
static aDat getNKeyBits ( int n, KEYBUF_PTR kp )
{
  aDat res = 0;
  int i;

  for ( i = 0 ; i < n ; i++ ) {
    res |= ( nextKeyBit(kp) << i );
  }
  return res;
}
#endif

#if !defined(USE_LIBGCRYPT)

// used by getkey if key is not strong enough
static BS bs;

/*
 * get key bits from 's' of the form:
 *  "str1,str2"
 */
static void getkey ( char *s , KEYBUF_PTR kp )
{
  char *c;
  unsigned char *src,*dst;
  unsigned int len;
  char *d;
#if !defined(USE_SHA1)
  byte *res;
  unsigned char *kdst;
#else
  unsigned int W[80];      // scratch used by sha1 algorithm
#endif

  memset(kp,0,sizeof(KEYBUF));
  kp->keyMax = RMDsize*2/8;

  c = strchr(s,',');
  if ( !c ) {
    printf("getkey: invalid key, missing ','\n");
    exit(0);
  }

  /* get first part of the key */
  len = (unsigned int)(c - s);
  d = malloc( len + 1 );
  assert(NULL!=d);
  src = s;
  dst = d;
  while ( *src != ',' ) {
    *dst++ = *src++;
  }
  *dst = 0;

#if defined ( CPTRACE )
  printf("getkey: <%s>\n",d);
#endif

#if defined(USE_SHA1)
  {
    unsigned int s = KEY_ASSIST;
    unsigned char *m_src,*m_dst;
    int m_i;

    m_src = (unsigned char *)&s;
    m_dst = (unsigned char *)&bs;

    for ( m_i = 0 ; m_i < sizeof(BS) ; m_i++ ) {
      m_dst [ m_i ] = m_src [ m_i % 4 ];
    }
  }

  {
    int len = strlen(d);
    char *nd = d;

    sha_init( (unsigned int *)kp->k );

    if ( len < 64 ) {
      int i;

      // key is not long enough
      nd = (char *)malloc ( 65 );
      assert(nd!=NULL);
      strcpy(nd,d);

      for ( i = len ; i < 64 ; i++ ) {
	// return some number of bits
	nd[i] = lfsr_poly_bits ( &bs, 8 );

#if 0
	printf("%s: key1 - adding key bit nd[%d] = 0x%02x\n",
	       __FUNCTION__,
	       i,nd[i] & 0xff);
#endif

      }
      nd[i] = 0;
    }

    src = nd;
    while ( strlen(src) >= 64 ) {
      sha_transform( (unsigned int *)kp->k, src, W);
      src += 1;
    }

    // zero and free resource
    zfree(nd);
  }
#else // USE_SHA1
  res = RMD(d);
  src = res;
  kdst = kp->k;
  len = RMDsize/8;
  while ( len-- > 0 ) {
    *kdst++ ^= *src++;
  }
#endif // USE_SHA1
	
  /* get the second part of the key */
  c++;
  len = strlen(c);
  zfree(d);
  d = malloc( len + 1 );
  assert(NULL!=d);
  src = c;
  dst = d;
  while ( *src ) {
    *dst++ = *src++;
  }
  *dst = 0;

#if defined ( CPTRACE )
  printf("getkey: <%s>\n",d);
#endif

#if defined(USE_SHA1)
  {
    int len = strlen(d);
    char *nd = d;

    sha_init( (unsigned int *)&kp->k[sizeof(kp->k)/2] );

    if ( len < 64 ) {
      int i;

      // key is not long enough
      nd = (char *)malloc ( 65 );
      assert(nd!=NULL);
      strcpy(nd,d);

      for ( i = len ; i < 64 ; i++ ) {
	// return some number of bits
	nd[i] = lfsr_poly_bits ( &bs, 8 );

#if 0
	printf("%s: key2 - adding key bit nd[%d] = 0x%02x\n",
	       __FUNCTION__,
	       i,nd[i] & 0xff);
#endif

      }
      nd[i] = 0;
    }

    src = nd;
    while ( strlen(src) >= 64 ) {
      sha_transform( (unsigned int *)&kp->k[sizeof(kp->k)/2], src, W);
      src += 1;
    }

    // zero and free resource
    zfree(nd);
  }
#else // USE_SHA1
  res = RMD(d);
  src = res;
  len = RMDsize/8;
  while ( len-- > 0 ) {
    *kdst++ ^= *src++;
  }
#endif // USE_SHA1

  // tidy up
#if defined(USE_SHA1)
  //memset(&bs,0,sizeof(BS));
  memset(W,0,sizeof(W));
#endif

  /* return to caller */
  if ( d ) zfree(d);
  return;
}
#endif // USE_LIBGCRYPT

#if 0
typedef struct keybuf_3 {
  int key_idx;             /* [0,1,2,...n] depending on which KEYBUF is current */
  int bits_used;           /* total bits used                                   */
  int max_key_groups;      /* KEYBUF_3_MAX_KEY_GROUPS                           */
  KEYBUF key_one;          /* a KEYBUF                                          */
  KEYBUF key_two;          /* ""                                                */
  KEYBUF key_three;        /* ""                                                */
  KEYBUF_128 key_four;     /* ""                                                */
} KEYBUF_3; *KEYBUF_3_PTR;
#endif

/*
 * get key bits from 's'
 */
void getkey_3 ( PGM_CTX *pgm_ctx, char *s , KEYBUF_3 *kp3 )
{
#if defined(USE_LIBGCRYPT)
  // use gcrypt library to build key bits
  unsigned char *keybuffer;
  int keysize;
  unsigned char salt [ 8 ];
  unsigned char *src,*dst;
  int s_len = strlen(s);
  gpg_error_t sts;

  /* initialize */
  kp3->max_key_groups = KEYBUF_3_MAX_KEY_GROUPS;
  kp3->key_idx = 0;
  kp3->bits_used = 0;
  memset(kp3->key_one  .k, 0, sizeof(kp3->key_one.k));
  memset(kp3->key_two  .k, 0, sizeof(kp3->key_two.k));
  memset(kp3->key_three.k, 0, sizeof(kp3->key_three.k));
  memset(kp3->key_four .k, 0, sizeof(kp3->key_four.k));

  kp3->key_one.keyMax   = RMDsize*2/8;
  kp3->key_two.keyMax   = RMDsize*2/8;
  kp3->key_three.keyMax = RMDsize*2/8;
  kp3->key_four.keyMax  = KEYBUF_128_SIZE;

  if ( !pgm_ctx->dibit_n_flag ) {
    // -a and -d ???
    if ( pgm_ctx->dibit_a_flag && pgm_ctx->dibit_d_flag ) {
      // yes, just read key info from our cache
      pgm_ctx->key_file_prev_offset = -1;

      // load up key data

      key_file_read ( pgm_ctx, kp3->key_one.k  , sizeof(kp3->key_one.k) );
      key_file_read ( pgm_ctx, kp3->key_two.k  , sizeof(kp3->key_two.k) );
      key_file_read ( pgm_ctx, kp3->key_three.k, sizeof(kp3->key_three.k) );
      key_file_read ( pgm_ctx, kp3->key_four.k, sizeof(kp3->key_four.k) );

      if ( trace_flag > 1 ) printf("%s: read all key data\n",__FUNCTION__);

    } else {
      // check for 0x form of key
      if ( '0' == s[0] && 'x' == s[1] ) {
	unsigned int kx;

	// yes, attempt to grab key from KEY_FILE_NAME
	sscanf(&s[2],"%x",&kx);

	// jump out to some random place, make sure we have enough remaining
	// tell key_file module
	pgm_ctx->key_file_offset      = kx;
	// zero any cache
	pgm_ctx->key_file_prev_offset = -1;
    
	if ( key_file_valid(pgm_ctx) ) {
      
	  if ( trace_flag > 1 )
	    printf("%s: pulling key from file <%s> at offset = 0x%x (%d)\n",
		   __FUNCTION__,
		   KEY_FILE_NAME,
		   kx,kx);
      
	  // parsel out bits
      
	  key_file_read ( pgm_ctx, kp3->key_one.k  , sizeof(kp3->key_one.k) );
	  key_file_read ( pgm_ctx, kp3->key_two.k  , sizeof(kp3->key_two.k) );
	  key_file_read ( pgm_ctx, kp3->key_three.k, sizeof(kp3->key_three.k) );
	  key_file_read ( pgm_ctx, kp3->key_four.k, sizeof(kp3->key_four.k) );
      
	} else {
	  if ( trace_flag > 1 )
	    printf("%s: Warning, can't open file <%s>, using input string with non-file key generator\n",
		   __FUNCTION__,
		   KEY_FILE_NAME);
	}
      }
    }
  } // dibit_n_flag

  //
  // use libgcrypt to generate bits
  //
  keybuffer = (unsigned char *)alloca (
				       (keysize = sizeof(kp3->key_one.k) +
					sizeof(kp3->key_two.k) +
					sizeof(kp3->key_three.k) +
					sizeof(kp3->key_four.k)) );
  assert(keybuffer!=NULL);

  // get salt from key
  dst = salt;
  src = s;
  {
    int i;
    for ( i = 0 ; i < sizeof(salt) ; i++ ) {
      dst [ i ] = s [ i % s_len ];
    }
  }

  // do the dew
  sts = gcry_kdf_derive ( s,s_len,
			  GCRY_KDF_ITERSALTED_S2K,GCRY_MD_SHA512,
			  salt, sizeof(salt),
			  16, keysize,keybuffer );
  if ( sts ) {
    printf("%s: gcry_kdf_derive failed with sts = %d\n",
	   __FUNCTION__,
	   sts);
    exit(0);
  }

  src = keybuffer;

  // xor in this key data
  {
    int i;
    int j = 0;

    // load key_one
    dst = kp3->key_one.k;
    for ( i = 0 ; i < sizeof(kp3->key_one.k) ; i++, j++ ) {
      dst[i] ^= src[j];
    }

    // load key_two
    dst = kp3->key_two.k;
    for ( i = 0 ; i < sizeof(kp3->key_two.k) ; i++, j++ ) {
      dst[i] ^= src[j];
    }

    // load key_three
    dst = kp3->key_three.k;
    for ( i = 0 ; i < sizeof(kp3->key_three.k) ; i++, j++ ) {
      dst[i] ^= src[j];
    }

    // load key_four
    dst = kp3->key_four.k;
    for ( i = 0 ; i < sizeof(kp3->key_four.k) ; i++, j++ ) {
      dst[i] ^= src[j];
    }
  }

  return;

#else // USE_LIBGCRYPT
  // use descrete 'c' code to build key bits

  char *tmp = NULL;
  char *tmp1 = NULL;
  char *c,*d;
  char *st;
#if defined ( CPTRACE )
  char *key1,*key2,*key3;
#endif
  int len;
  char *sc = alloca(strlen(s)+1);
  unsigned int zorch = 0xbeef;

  memset(kp3,0,sizeof(KEYBUF_3));

  if ( trace_flag > 1 ) printf("%s: entry, key = <%s>\n",__FUNCTION__,s);

  /* initialize */
  kp3->max_key_groups = KEYBUF_3_MAX_KEY_GROUPS - 1;
  kp3->key_idx = 0;
  kp3->bits_used = 0;
  memset(kp3->key_one.k,0,sizeof(kp3->key_one.k));
  memset(kp3->key_two.k,0,sizeof(kp3->key_two.k));
  memset(kp3->key_three.k,0,sizeof(kp3->key_three.k));
  memset(kp3->key_four.k,0,sizeof(kp3->key_four.k));

  // -m and -d ???
  if ( pgm_ctx->dibit_m_flag && pgm_ctx->dibit_d_flag ) {

    pgm_ctx->key_file_prev_offset = -1;

    // load up key data

    key_file_read ( pgm_ctx, kp3->key_one.k  , sizeof(kp3->key_one.k) );
    key_file_read ( pgm_ctx, kp3->key_two.k  , sizeof(kp3->key_two.k) );
    key_file_read ( pgm_ctx, kp3->key_three.k, sizeof(kp3->key_three.k) );

    kp3->max_key_groups += 1;
    key_file_read ( pgm_ctx, kp3->key_four.k, sizeof(kp3->key_four.k) );
    kp3->key_four.keyMax = KEYBUF_128_SIZE;

    if ( trace_flag > 1 ) printf("%s: read all key data\n",__FUNCTION__);

  } else {
    // check for 0x form of key
    if ( '0' == s[0] && 'x' == s[1] ) {
      unsigned int kx;

      // yes, attempt to grab key from KEY_FILE_NAME
      sscanf(&s[2],"%x",&kx);

      // jump out to some random place, make sure we have enough remaining
      pgm_ctx->sql_next_key_offset  = kx;
      // tell key_file module
      pgm_ctx->key_file_offset      = kx;
      // zero any cache
      pgm_ctx->key_file_prev_offset = -1;

      if ( key_file_valid(pgm_ctx) ) {

	if ( trace_flag > 1 )
	  printf("%s: pulling key from file <%s> at offset = 0x%x (%d)\n",
		 __FUNCTION__,
		 KEY_FILE_NAME,
		 kx,kx);

	// parsel out bits

	key_file_read ( pgm_ctx, kp3->key_one.k  , sizeof(kp3->key_one.k) );
	key_file_read ( pgm_ctx, kp3->key_two.k  , sizeof(kp3->key_two.k) );
	key_file_read ( pgm_ctx, kp3->key_three.k, sizeof(kp3->key_three.k) );

	kp3->max_key_groups += 1;
	key_file_read ( pgm_ctx, kp3->key_four.k, sizeof(kp3->key_four.k) );
	kp3->key_four.keyMax = KEYBUF_128_SIZE;
      
	// done if no '-' in string
	// else we are going to run the string through RMD and xor those
	// results with whatever came out of the key file
	if ( NULL == strchr(s,'-') ) return;

	if ( trace_flag > 1 ) printf("%s: xoring in key string\n",__FUNCTION__);

      } else {
	printf("%s: Warning, can't open file <%s>, using input string with non-file key generator\n",
	       __FUNCTION__,
	       KEY_FILE_NAME);
      }
    }
  }

  // try to make key stronger

  // no ',' allowed, we'll add them in this routine
  strcpy(sc,s);
  c = sc;
  while ( *c ) {
    if ( *c == ',' ) *c = '?';
    c += 1;
  }
    
  // Actually, we should just look at the trial output of the RMD160
  // and if it matches, we should muck with the current key
  // so it doesn't.

  // don't let key be 32 chars
  if ( !(32 % (len=strlen(sc))) || len < 4 ) {
    st = (char *)alloca(len + 5 + 1);
    memcpy(st,sc,len);

    st[len + 4] = 0;
    st[len + 5] = 0;

    memcpy(&st[len],"12345",len < 4 ? 4 : 5);

  } else {
    st = sc;
  }

  // build up buffer tmp1 from key 's' and
  // make sure thare are 6 commas added
  {
    char *src,*dst;
    int cnt;

    tmp1 = (char *)alloca ( 192 + 8 );
    dst = tmp1;
    src = st;

    // get string macro
#define GETSTR(term) \
    cnt = 32; \
    while ( cnt-- > 0 ) { \
      if ( *src == 0 ) src = st; \
      *dst = *src; \
      dst += 1; \
      src += 1; \
    } \
    *dst++ = term;

    // get strings
    GETSTR(',');
    GETSTR(',');
    GETSTR(',');
    GETSTR(',');
    GETSTR(',');
    GETSTR('\0');
  }

  if ( trace_flag > 1 ) printf("%s: <%s>\n",__FUNCTION__,tmp1);

  tmp = strdup( tmp1 );
  assert(NULL!=tmp);

  /* get key_one */
  d = tmp;
  c = strchr(d,',');
  assert(c!=NULL);
  c++;
  c = strchr(c,',');
  assert(c!=NULL);
  *c = 0;
  getkey ( d, &kp3->key_one );

#if defined ( CPTRACE )
  key1 = d;
#endif

  /* get key_two */
  c++; d = c;
  c = strchr(d,',');
  assert(c!=NULL);
  c++;
  c = strchr(c,',');
  assert(c!=NULL);
  *c = 0;
  getkey ( d, &kp3->key_two );

#if defined ( CPTRACE )
  key2 = d;
#endif

  /* get key_three */
  c++; d = c;
  c = strchr(c,',');
  assert(c!=NULL);
  getkey ( d, &kp3->key_three );

#define CMP(targ,src) 0 == memcmp(targ,src,RMDsize/8) ? 1 : 0
#define ZORCH(targ) ({ \
      int iterator; \
      unsigned char *tgt = targ; \
      for ( iterator = 0 ; iterator < RMDsize/8 ; iterator++, tgt += 1 ) { \
	*tgt ^= zorch; \
	zorch += 1; \
      } \
    })
 
  // make sure all keys are different
  while ( 1 ) {
    static int first = 1;

    if ( !first ) {
      if ( trace_flag > 1 ) printf("%s: duplicate binary key detected and corrected\n",
			       __FUNCTION__);
    }
    first = 0;

    // k3 - make sure two halves are different
    if ( CMP( kp3->key_three.k , kp3->key_one.k ) ) {
      // they are the same
      ZORCH(kp3->key_three.k);
      continue;
    }
    if ( CMP( kp3->key_three.k , &kp3->key_one.k[RMDsize/8] ) ) {
      // they are the same
      ZORCH(kp3->key_three.k);
      continue;
    }
    if ( CMP( kp3->key_three.k , kp3->key_two.k ) ) {
      // they are the same
      ZORCH(kp3->key_three.k);
      continue;
    }
    if ( CMP( kp3->key_three.k , &kp3->key_two.k[RMDsize/8] ) ) {
      // they are the same
      ZORCH(kp3->key_three.k);
      continue;
    }
    if ( CMP( kp3->key_three.k , &kp3->key_three.k[RMDsize/8] ) ) {
      // they are the same
      ZORCH(kp3->key_three.k);
      continue;
    }

    // k2 - make sure two halves are different
    if ( CMP( kp3->key_two.k , kp3->key_one.k ) ) {
      // they are the same
      ZORCH(kp3->key_two.k);
      continue;
    }
    if ( CMP( kp3->key_two.k , &kp3->key_one.k[RMDsize/8] ) ) {
      // they are the same
      ZORCH(kp3->key_two.k);
      continue;
    }
    if ( CMP( kp3->key_two.k , &kp3->key_two.k[RMDsize/8] ) ) {
      // they are the same
      ZORCH(kp3->key_two.k);
      continue;
    }
    if ( CMP( kp3->key_two.k , kp3->key_three.k ) ) {
      // they are the same
      ZORCH(kp3->key_two.k);
      continue;
    }
    if ( CMP( kp3->key_two.k , &kp3->key_three.k[RMDsize/8] ) ) {
      // they are the same
      ZORCH(kp3->key_three.k);
      continue;
    }

    // k1 - make sure two halves are different
    if ( CMP( kp3->key_one.k , &kp3->key_one.k[RMDsize/8] ) ) {
      // they are the same
      ZORCH(kp3->key_one.k);
      continue;
    }
    if ( CMP( kp3->key_one.k , kp3->key_two.k ) ) {
      // they are the same
      ZORCH(kp3->key_one.k);
      continue;
    }
    if ( CMP( kp3->key_one.k , &kp3->key_two.k[RMDsize/8] ) ) {
      // they are the same
      ZORCH(kp3->key_one.k);
      continue;
    }
    if ( CMP( kp3->key_one.k , kp3->key_three.k ) ) {
      // they are the same
      ZORCH(kp3->key_one.k);
      continue;
    }
    if ( CMP( kp3->key_one.k , &kp3->key_three.k[RMDsize/8] ) ) {
      // they are the same
      ZORCH(kp3->key_one.k);
      continue;
    }

    // done
    break;
  } // while 1

#if defined ( CPTRACE )
  key3 = d;
  printf("getkey_3: key1 = <%s>, key2 = <%s>, key3 = <%s>\n",
	 key1,key2,key3);
#endif

  /* return to caller */
  if ( tmp ) zfree ( tmp );

#endif // USE_LIBGCRYPT
}

#if 0
/* get n key bits 3, wrap across the three key
 * buffers only if necessary
 */
aDat getNKeyBits_3 ( PGM_CTX *pgm_ctx, int n, KEYBUF_3 *kp )
{
  KEYBUF *k;
  aDat res = 0;
  int i;

  // make sure we point to proper key group
  for ( i = 0 ; i < n ; i++ ) {
    switch ( kp->key_idx )
      {
      case 0:
	k = &kp->key_one;
	break;
	
      case 1:
	k = &kp->key_two;
	break;
	
      case 2:
	k = &kp->key_three;
	break;

      case 3:
	// Note: Cheat a bit - KEYBUF and KEYBUF_3 must be the same except for the key size
	k = (KEYBUF *)&kp->key_four;
	break;
	
      default:
	assert(1==0);
      }

    res |= ( nextKeyBit(k) << i );
    kp->bits_used++;

    /* handle wrap to next KEYBUF */
    if ( did_wrap_true ( k ) ) {
      kp->key_idx++;
      if ( kp->key_idx >= kp->max_key_groups ) {
	kp->key_idx = 0;

#if defined(USE_AES)
	// lets encrypt our keys using aes 'b'
	{
	  unsigned char *kc;
	  int i;

	  if ( 1 || trace_flag ) printf("%s: encrypting all keys\n",__FUNCTION__);

	  //
	  // key_one
	  //
	  kc = kp->key_one.k;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE/2;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  //
	  // key_two
	  //
	  kc = kp->key_two.k;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE/2;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  //
	  // key_three
	  //
	  kc = kp->key_three.k;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE/2;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  //
	  // key_four
	  //
	  kc = kp->key_four.k;
	  for ( i = 0 ; i < KEYBUF_128_SIZE/AES_BLOCK_SIZE ; i++, kc += AES_BLOCK_SIZE ) {
	    aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
			 pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
			 kc);
	    memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);
	  }
	}
#endif // USE_AES

      }
    }

  } /* for */

  /* return to caller */
  return res;
}
#endif // 0

#if 0
/* XOR the key with itself to use all
 * key bits.
 *
 * n - unused bits to use up
 */
void xor_key_bits ( int n, KEYBUF_3_PTR kp )
{
  aDat x;
  int cnt;
  int i;
  KEYBUF_PTR key_ptr;

  while ( n > 0 ) {
    cnt = n > 8 ? 8 : n;

    /* get those bits */
    x = getNKeyBits_3 ( cnt, kp );

    /* XOR */
    key_ptr = &kp->key_one;
    for ( i = 0 ; i < RMDsize*2/8 ; i++ ) {
      key_ptr->k[i] ^= x;
    }
    key_ptr = &kp->key_two;
    for ( i = 0 ; i < RMDsize*2/8 ; i++ ) {
      key_ptr->k[i] ^= x;
    }
    key_ptr = &kp->key_three;
    for ( i = 0 ; i < RMDsize*2/8 ; i++ ) {
      key_ptr->k[i] ^= x;
    }

    /* decrement our count */
    n -= cnt;
  }

  /* reset key count and usage indexes */
  kp->key_idx       = 0;
  kp->key_one.idx   = kp->key_one.bit   = 0;
  kp->key_two.idx   = kp->key_two.bit   = 0;
  kp->key_three.idx = kp->key_three.bit = 0;

  /* return to caller */
}
#endif

/*
 * iterator code
 */

#if 0
/* included for documentation only, from keykey.h */

/* iterate through a keybuf_3 */
typedef struct keybuf_3_iterator {

  /* ptr to keybuf_3 */
  KEYBUF_3_PTR kb;

  /* which keybuf */
  int key_idx;             /* [0,1,2] depending on which KEYBUF is current */
  int bits_used;           /* total bits used                              */

  /* for current keybuf */
  int idx;                 /* index into k    */
  int bit;                 /* bit mask [0..7] */

} KEYBUF_3_ITERATOR, *KEYBUF_3_ITERATOR_PTR;
#endif /* 0 */

/* initialize new iterator */
void kb_iterator_new ( KEYBUF_3_ITERATOR_PTR ki,
		       KEYBUF_3_PTR          kb )
{
  memset( ki, 0 , sizeof( KEYBUF_3_ITERATOR ));
  ki->kb = kb;
}

/* get next key bit from kp for the iterator */
static int nextKeyBit_iterator ( KEYBUF_PTR kp,
				 int *bit,
				 int *idx )
{
  int res;

  /* get the bit */
  res = kp->k[*idx] & (1<<(*bit)) ? 1 : 0;

  /* update indexes to next bit, wrap if necessary */
  *bit += 1;
  if ( *bit > 7 ) {
    *bit = 0;
    *idx += 1;
    if ( *idx >= kp->keyMax ) {
      *idx = 0;
    }
  }

  /* return bit to caller */
  return res;
}

/* did iterator wrap ??? */
static int did_wrap_true_iterator ( KEYBUF_3_ITERATOR_PTR ki )
{
  if ( 0 == ki->bit && 0 == ki->idx ) {
    return 1;
  }
  return 0;
}

/* get 'n' bits from key interator 'ki' */
aDat getNKeyBits_3_iterator ( PGM_CTX *pgm_ctx, int n, KEYBUF_3_ITERATOR_PTR ki )
{
  KEYBUF_PTR   k;
  KEYBUF_3_PTR kp;

  aDat res = 0;
  int i;

  kp = ki->kb;
  assert(NULL!=kp);

  for ( i = 0 ; i < n ; i++ ) {
    switch ( ki->key_idx )
      {
      case 0:
	k = &kp->key_one;
	break;
	
      case 1:
	k = &kp->key_two;
	break;
	
      case 2:
	k = &kp->key_three;
	break;
	
      default:
	assert(1==0);
      }

    res |= ( nextKeyBit_iterator(k,&ki->bit,&ki->idx) << i );

    /* statistics */
    ki->bits_used += 1;

    /* handle wrap to next KEYBUF */
    if ( did_wrap_true_iterator ( ki ) ) {
      ki->key_idx += 1;
      if ( ki->key_idx > 2 ) {
	ki->key_idx = 0;

#if defined(USE_AES)
	// lets encrypt our keys using aes 'b'
	{
	  unsigned char *kc;
	  int i;

	  if ( trace_flag > 1 ) printf("%s: encrypting all keys\n",__FUNCTION__);

	  //
	  // key_one
	  //
	  kc = kp->key_one.k;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE/2;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  //
	  // key_two
	  //
	  kc = kp->key_two.k;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE/2;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  //
	  // key_three
	  //
	  kc = kp->key_three.k;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  kc += AES_BLOCK_SIZE/2;
	  aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
		       pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
		       kc);
	  memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);

	  //
	  // key_four
	  //
	  kc = kp->key_four.k;
	  for ( i = 0 ; i < KEYBUF_128_SIZE/AES_BLOCK_SIZE ; i++, kc += AES_BLOCK_SIZE ) {
	    aes_encrypt( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
			 pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,
			 kc);
	    memcpy(kc,pgm_ctx->pgm_ctx_aes_b.crypto_aes_register_a,AES_BLOCK_SIZE);
	  }
	}
#endif // USE_AES

      }
    }

  } /* for */

  /* return to caller */
  return res;
}
