#ifndef __aes_pseudo_h__
#define __aes_pseudo_h__

typedef struct aes_pseudo_struct_t {

  // bind a lfsr pair to an aes context
  D_LFSR *aes_pseudo_d_lfsr;
  struct pgm_ctx_aes_struct_t *aes_pgm_ctx_aes;

} AES_PSEUDO;

// bind
void aes_pseudo_bind ( D_LFSR *d_lfsr, struct pgm_ctx_aes_struct_t *aes_ctx, AES_PSEUDO *aes_pseudo );

// get one bit from AES_PSEUDO
unsigned int aes_pseudo_get_one_bit ( AES_PSEUDO *aes_pseudo );

// get multi-bits from AES_PSEUDO
unsigned int aes_pseudo_get_multi_bit ( AES_PSEUDO *aes_pseudo, int cnt );

#endif // __aes_pseudo_h__
