// special encryption for last block

#include "config.h"

#if defined(USE_LIBGCRYPT)
#include <gcrypt.h>
#endif

// obscure the last block in a file
void last_block_obscure ( unsigned int fd,
			  unsigned char *key )
{
  unsigned char last_block [ AES_BLOCK_SIZE ];
  BS bs;
  unsigned char salt [ 8 ];
  unsigned char *src,*dst;
  int key_len = strlen(key);
  gpg_error_t sts;
  int rounds = 10 + key_len;
  // this poly has a size of 10^50
  int poly_array[5] = {168,166,153,151,-1};
  int i;

  // get salt from key
  dst = salt;
  src = key;
  for ( i = 0 ; i < sizeof(salt) ; i++ ) {
    dst [ i ] = key [ i % key_len ];
  }

  // get initial lfsr
  sts = gcry_kdf_derive ( key,key_len,
			  GCRY_KDF_ITERSALTED_S2K,GCRY_MD_SHA512,
			  salt, sizeof(salt),
			  rounds, // rounds
			  sizeof(BS),bs.bigSeed );

  // read last block from file
  rw(mf_lseek,fd,-AES_BLOCK_SIZE,SEEK_END);
  rw(mf_read,fd,last_block,AES_BLOCK_SIZE);

  for ( i = 0 ; i < AES_BLOCK_SIZE ; i++ ) {
    unsigned int dat;

    // get lfsr bits
    dat = get_lfsr_bits ( 8, &bs, poly_array );

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

    // obscure
    last_block [ i ] ^= dat;
  }

  // write last block from file
  rw(mf_lseek,fd,-AES_BLOCK_SIZE,SEEK_END);
  rw(mf_write,fd,last_block,AES_BLOCK_SIZE);

  // done
}

