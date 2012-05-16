#ifndef __bbs_pseudo_h__
#define __bbs_pseudo_h__

// init
void bbs_pseudo_init ( PGM_CTX *pgm_ctx );

// get one bit from BBS_PSEUDO
unsigned int bbs_pseudo_get_one_bit ( PGM_CTX *pgm_ctx );

// get multi-bits from BBS_PSEUDO
unsigned int bbs_pseudo_get_multi_bit ( PGM_CTX *pgm_ctx, int cnt );

#endif // __bbs_pseudo_h__
