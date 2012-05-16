#ifndef __lfsr_h__
#define __lfsr_h__

#define aDat unsigned int

// define 192 bits
// Note: Must be multiple of 4, ie BIG_SEED_MAX % 4 = 0
#define BIG_SEED_MAX 24

typedef struct bs_struct_t {
  unsigned char bigSeed [ BIG_SEED_MAX ];
} BS , BIG_SEED, *BS_PTR;

typedef struct dual_lfsr_struct {
  BS bs_A;               /* bit shifter A */
  BS bs_B;               /* bit shifter B */
  int *poly_A;           /* poly A        */
  int *poly_B;           /* poly B        */
} D_LFSR, *D_LFSR_PTR;

#define MAX_POLY_ARRAY 16
//extern int *poly_array[MAX_POLY_ARRAY];

struct pgm_ctx_struct_t;

/* initialize the lfsr module */
void lfsr_init( struct pgm_ctx_struct_t *pgm_ctx );

/* get dual_lfsr_bits */
//
// Note: we shift two polys, if the first one returns true,
//       we 'or' in the second and count it as a bit,
//       else we continue.
//
unsigned int get_dual_lfsr_bits ( int num_bits, D_LFSR_PTR x );

struct keybuf_3_iterator_t;

/* init_dual_lfsr_from_key */
void init_dual_lfsr_from_key ( struct pgm_ctx_struct_t *pgm_ctx,
			       D_LFSR *x,               /* output structure      */
			       struct keybuf_3_iterator_t *kb3_i /* key bits              */
			       );

// get lfsr bits
unsigned int get_lfsr_bits ( int num_bits, BS *bs, int *poly_array );

#endif /* __lfsr_h__ */
