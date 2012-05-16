#ifndef __getkey_h__
#define __getkey_h__

#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "lfsr.h"

// Note: Cheat a bit - KEYBUF and KEYBUF_3 must be the same except for the key size
typedef struct keybuf_struct_t {
  int idx;                       /* index into k    */
  int bit;                       /* bit mask [0..7] */
  int keyMax;                    /* RMDsize*2/8     */
  int usedBits;                  /* no used bits    */
  unsigned char k[RMDsize*2/8];  /* key bits        */
} KEYBUF, *KEYBUF_PTR;

// Note: KEYBUF_128_SIZE must be multiple of AES_BLOCK_SIZE
#define KEYBUF_128_SIZE 128
typedef struct keybuf_128_struct_t {
  int idx;                          /* index into k    */
  int bit;                          /* bit mask [0..7] */
  int keyMax;                       /* KEYBUF_128_SIZE */
  int usedBits;                     /* no used bits    */
  unsigned char k[KEYBUF_128_SIZE]; /* key bits        */
} KEYBUF_128;

#define KEYBUF_3_MAX_KEY_GROUPS 4

typedef struct keybuf_3_struct_t {
  int key_idx;             /* [0,1,2,...n] depending on which KEYBUF is current */
  int bits_used;           /* total bits used                                   */
  int max_key_groups;      /* KEYBUF_3_MAX_KEY_GROUPS                           */
  KEYBUF key_one;          /* a KEYBUF                                          */
  KEYBUF key_two;          /* ""                                                */
  KEYBUF key_three;        /* ""                                                */
  KEYBUF_128 key_four;     /* ""                                                */
} KEYBUF_3, *KEYBUF_3_PTR;

/* iterate through a keybuf_3 */
typedef struct keybuf_3_iterator_t {

  /* ptr to keybuf_3 */
  KEYBUF_3 *kb;

  /* which keybuf */
  int key_idx;             /* [0,1,2] depending on which KEYBUF is current */
  int bits_used;           /* total bits used                              */

  /* for current keybuf */
  int idx;                 /* index into k    */
  int bit;                 /* bit mask [0..7] */

} KEYBUF_3_ITERATOR, *KEYBUF_3_ITERATOR_PTR;

struct pgm_ctx_struct_t;

/*
 * get key bits from 's' of the form:
 *  "str1,str2,str3,str4,str5,str6"
 */
void getkey_3 ( struct pgm_ctx_struct_t *pgm_ctx, char *s , KEYBUF_3_PTR kp3 );

/* get n key bits 3 */
struct pgm_ctx_struct_t;
aDat getNKeyBits_3 ( struct pgm_ctx_struct_t *pgm_ctx, int n, KEYBUF_3 *kp3 );

/* show bits_used */
void show_bits_used ( KEYBUF_3_PTR kp_3 );

/* XOR the key with itself to use all
 * key bits.
 *
 * n - unused bits to use up
 */
void xor_key_bits ( int n, KEYBUF_3_PTR kp );

/*
 * key iterator
 */
/* initialize new iterator */
void kb_iterator_new ( KEYBUF_3_ITERATOR_PTR ki,
		       KEYBUF_3_PTR          kb );

/* get 'n' bits from key interator 'ki' */
aDat getNKeyBits_3_iterator ( struct pgm_ctx_struct_t *pgm_ctx, int n, KEYBUF_3_ITERATOR_PTR ki );

#endif /* __getkey_h__ */
