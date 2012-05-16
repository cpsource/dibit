
#include "config.h"

#if defined(USE_LIBGCRYPT)
#include <gcrypt.h>
#endif

extern int trace_flag;

// init an aes_cfb with a key
void aes_cfb_init ( PGM_CTX *pgm_ctx,
		    AES_CFB *aes_cfb,
		    char *key )
{
  // use gcrypt library to build key bits
  unsigned char keybuffer [ 32 ];
  unsigned char salt [ 8 ];
  unsigned char *src,*dst;
  int key_len = strlen(key);
  gpg_error_t sts;
  int i;

  //
  // get keybuffer
  //

  // get salt from key
  dst = salt;
  src = key;
  for ( i = 0 ; i < sizeof(salt) ; i++ ) {
    dst [ i ] = key [ i % key_len ];
  }

  // get keybuffer
  sts = gcry_kdf_derive ( key,key_len,
			  GCRY_KDF_ITERSALTED_S2K,GCRY_MD_SHA512,
			  salt, sizeof(salt),
			  16, sizeof(keybuffer),keybuffer );
  if ( sts ) {
    printf("%s: gcry_kdf_derive failed with sts = %d\n",
	   __FUNCTION__,
	   sts);
    exit(0);
  }

  // 16 bytes -> regA
  src = keybuffer;
  memcpy( aes_cfb->regA, src, 16 );

  // initialize AES
  src += 16;
  sts = crypto_aes_set_key( &aes_cfb->aes_ctx,
			    src,
			    16 );
  if ( sts ) {
    printf("%s: crypto_aes_set_key() failed with sts = %d\n",
	   __FUNCTION__,sts);
    exit(0);
  }

}

// encrypt
void aes_cfb_encrypt ( PGM_CTX *pgm_ctx,
		       AES_CFB *aes_cfb,
		       int block_count,
		       unsigned char *cleartext,
		       unsigned char *cryptext )
{
  int i;

  while ( block_count-- > 0 ) {

    //printf("%s: block_count = %d\n",__FUNCTION__,block_count);

    // A encrypted to B

    aes_encrypt( &aes_cfb->aes_ctx,
		 aes_cfb->regB,     /* out */
		 aes_cfb->regA      /* in  */ );

    // clear XOR B

    for ( i = 0 ; i < 16 ; i++ ) {
      aes_cfb->regB[i] ^= cleartext[i];
    }

    // B -> cryptext
    memcpy(cryptext,aes_cfb->regB,16);

    // B -> A
    memcpy(aes_cfb->regA,aes_cfb->regB,16);

    // update ptrs
    cleartext += 16;
    cryptext  += 16;
  }
}

// decrypt
void aes_cfb_decrypt ( PGM_CTX *pgm_ctx,
		       AES_CFB *aes_cfb,
		       int block_count,
		       unsigned char *cleartext,
		       unsigned char *cryptext )
{
  int i;

  while ( block_count-- > 0 ) {

    //printf("%s: block_count = %d\n",__FUNCTION__,block_count);

    // A encrypted to B

    aes_encrypt( &aes_cfb->aes_ctx,
		 aes_cfb->regB,     /* out */
		 aes_cfb->regA      /* in  */ );

    // crypt XOR B

    for ( i = 0 ; i < 16 ; i++ ) {
      aes_cfb->regB[i] ^= cryptext[i];
    }

    // crypt -> A
    memcpy(aes_cfb->regA,cryptext,16);

    // B -> cleartext
    memcpy(cleartext,aes_cfb->regB,16);

    // update ptrs
    cleartext += 16;
    cryptext  += 16;
  }
}

#if defined(CP_TEST)

AES_CFB aes_cfb;
AES_CFB aes_cfb_d;
unsigned char test_buf [ 32 ];

int main ( int argc, char *argv[] )
{
  int i;

  aes_cfb_init ( NULL,
		 &aes_cfb,
		 "test" );
  for ( i = 0 ; i < 32 ; i++ ) {
    test_buf [ i ] = i;
  }

  printf("before\n");
  for ( i = 0 ; i < 32 ; i++ ) {
    printf("test_buf [ %02d ] = 0x%02x (%d)\n",
	   i, test_buf[i]&0xff,test_buf[i]&0xff );
  }

  aes_cfb_encrypt ( NULL,
		    &aes_cfb,
		    2,
		    test_buf, test_buf );

  printf("encrypt\n");
  for ( i = 0 ; i < 32 ; i++ ) {
    printf("test_buf [ %02d ] = 0x%02x (%d)\n",
	   i, test_buf[i]&0xff,test_buf[i]&0xff );
  }

  aes_cfb_init ( NULL,
		 &aes_cfb_d,
		 "test" );

  aes_cfb_decrypt ( NULL,
		    &aes_cfb_d,
		    2,
		    test_buf, test_buf );

  printf("after\n");
  for ( i = 0 ; i < 32 ; i++ ) {
    printf("test_buf [ %02d ] = 0x%02x (%d)\n",
	   i, test_buf[i]&0xff,test_buf[i]&0xff );
  }

  return 0;
}

#endif // CP_TEST
