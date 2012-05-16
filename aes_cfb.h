#ifndef __aes_cfb_h__
#define __aes_cfb_h__

typedef struct aes_cfb_struct_t {

  struct crypto_aes_ctx aes_ctx;
  unsigned char regA [ 16 ];
  unsigned char regB [ 16 ];

} AES_CFB;

// init an aes_cfb with a key
void aes_cfb_init ( PGM_CTX *pgm_ctx,
		    AES_CFB *aes_cfb,
		    char *key );
// encrypt
void aes_cfb_encrypt ( PGM_CTX *pgm_ctx,
		       AES_CFB *aes_cfb,
		       int block_count,
		       unsigned char *cleartext,
		       unsigned char *cryptext );
// decrypt
void aes_cfb_decrypt ( PGM_CTX *pgm_ctx,
		       AES_CFB *aes_cfb,
		       int block_count,
		       unsigned char *cleartext,
		       unsigned char *cryptext );

#endif // __aes_cfb_h__
