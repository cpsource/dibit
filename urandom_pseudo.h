#ifndef __urandom_pseudo_h__
#define __urandom_pseudo_h__

// init
void urandom_pseudo_init ( PGM_CTX *pgm_ctx );
// get some bytes
void urandom_randbytes(PGM_CTX *pgm_ctx, char *retbuf, size_t nbytes);
// get one bit from urandom_pseudo
unsigned int urandom_pseudo_get_one_bit ( PGM_CTX *pgm_ctx );
// get multi-bits from urandom_pseudo
unsigned int urandom_pseudo_get_multi_bit ( PGM_CTX *pgm_ctx, int cnt );

#endif // __urandom_pseudo_h__
