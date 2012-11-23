// special encryption for last block

#include "config.h"

#if defined(USE_LIBGCRYPT)
#include <gcrypt.h>
#endif

#if defined(USE_TRIVIUM)
#include "trivium.h"
#endif

extern int trace_flag;

// the three amigos from wikipedia

#if 0
/* Add two numbers in a GF(2^8) finite field */
static uint8_t gadd(uint8_t a, uint8_t b) {
        return a ^ b;
}
 
/* Subtract two numbers in a GF(2^8) finite field */
static uint8_t gsub(uint8_t a, uint8_t b) {
        return a ^ b;
}
#endif
 
/* Multiply two numbers in the GF(2^8) finite field defined 
 * by the polynomial x^8 + x^4 + x^3 + x + 1 */
static uint8_t gmul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        uint8_t counter;
        uint8_t hi_bit_set;
        for (counter = 0; counter < 8; counter++) {
                if (b & 1) 
                        p ^= a;
                hi_bit_set = (a & 0x80);
                a <<= 1;
                if (hi_bit_set) 
                        a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
                b >>= 1;
        }
        return p;
}

// obscure the last block in a file
void last_block_obscure ( unsigned char *array,
			  unsigned char *key )
{
  BS bs;
  unsigned char salt [ 8 ];
  unsigned char *src,*dst;
  int key_len = strlen(key);
  gpg_error_t sts;
  int rounds = 10 + key_len;
  // this poly has a size of 10^50
  int poly_array[5] = {168,166,153,151,-1};
  int i;
#if defined(USE_TRIVIUM)
  trivium_ctx_t trivium_ctx;
  unsigned char trivium_dat;
#endif

#if 0
  {
    int j;
    printf("%s: initial array: ",__FUNCTION__);
    for ( j = 0 ; j < AES_BLOCK_SIZE ; j++ ) {
      printf("0x%02x ",array[j] & 0xff);
    }
    printf("\n");
  }
#endif

  // get salt from key
  dst = salt;
  src = key;
  for ( i = 0 ; i < sizeof(salt) ; i++ ) {
    dst [ i ] = key [ i % key_len ];
  }

  {
#if defined(USE_TRIVIUM)
    struct {
      unsigned char triv_key [ 10 ];
      unsigned char triv_vec [ 10 ];
      BS triv_bs;
    } x[1];

    // get initial lfsr
    sts = gcry_kdf_derive ( key,key_len,
			    GCRY_KDF_ITERSALTED_S2K,GCRY_MD_SHA512,
			    salt, sizeof(salt),
			    rounds, // rounds
			    sizeof(x),x );

    memcpy(bs.bigSeed,x[0].triv_bs.bigSeed,sizeof(BS));

    trivium_init( x[0].triv_key, sizeof(x[0].triv_key)*8,
		  x[0].triv_vec, sizeof(x[0].triv_vec)*8,
		  &trivium_ctx );

#else // USE_TRIVIUM

    // get initial lfsr
    sts = gcry_kdf_derive ( key,key_len,
			    GCRY_KDF_ITERSALTED_S2K,GCRY_MD_SHA512,
			    salt, sizeof(salt),
			    rounds, // rounds
			    sizeof(BS),bs.bigSeed );

#endif // USE_TRIVIUM
  }

  for ( i = 0 ; i < AES_BLOCK_SIZE ; i++ ) {
    unsigned int dat;

      // get 'good' lfsr bits
    while ( 1 ) {
      dat = get_lfsr_bits ( 8, &bs, poly_array );
      if ( 0 == dat || 0xff == dat )
	continue;
      break;
    }

#if defined(USE_TRIVIUM)

    // get 'good' trivium bits
    while ( 1 ) {
      trivium_dat = trivium_getbyte(&trivium_ctx);
      if ( 0 == trivium_dat || 0xff == trivium_dat )
	continue;
      break;
    }

#if 0
    printf("%s: dat = 0x%02x, trivium_dat = 0x%02x\n",
	   __FUNCTION__,
	   dat & 0xff,
	   trivium_dat & 0xff );
#endif

    /* Multiply two numbers in the GF(2^8) finite field defined 
     * by the polynomial x^8 + x^4 + x^3 + x + 1 */
    dat = gmul(dat,trivium_dat);

    if ( trace_flag > 1 )
      printf("%s: after mul, dat = 0x%02x\n",
	     __FUNCTION__,
	     dat & 0xff);

#else // USE_TRIVIUM

    switch ( (i | key [ i % key_len ]) & 0xf ) {
    case 13:
      get_lfsr_bits ( 1, &bs, poly_array );
      /* fallthrough */
    case 11:
      get_lfsr_bits ( 1, &bs, poly_array );
      /* fallthrough */
    case 7:
      get_lfsr_bits ( 1, &bs, poly_array );
      /* fallthrough */
    case 5:
      get_lfsr_bits ( 1, &bs, poly_array );
      /* fallthrough */
    case 3:
      get_lfsr_bits ( 1, &bs, poly_array );
      /* fallthrough */
    }

#endif // USE_TRIVIUM

    // obscure
    array [ i ] ^= dat;
  }

#if 0
  {
    int j;
    printf("%s: final array  : ",__FUNCTION__);
    for ( j = 0 ; j < AES_BLOCK_SIZE ; j++ ) {
      printf("0x%02x ",array[j] & 0xff);
    }
    printf("\n");
  }
#endif

  // done
}
