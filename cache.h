#ifndef __cache_h__
#define __cache_h__

struct ce_q_t {
  struct ce_q_t *q_forw;
  struct ce_q_t *q_back;
};

typedef struct cache_struct_entry_t {
  struct ce_q_t q;
  int bit_offset; // 0,1,2,...bit-max-1
  int off;        // byte offset into array
  int bit;        // 0..7
} CE;

typedef struct cache_ctx_t {
  struct ce_q_t ce_q;
} CTX;

// create an initial ctx
CTX *cache_ctx_new ( void );

// init ces
void cache_init_ces ( CTX *ctx, int bit_max );

// find idx and bit for a given bit_offset
// return value
int cache_find_dibit ( CTX *ctx, unsigned char *array, int bit_offset );

#if defined(USE_RBIT_TEST)
// find the bit number in rbit file
//
// Note: This returns a dibit offset, NOT the bit offset
//
int cache_find_rbit ( CTX *ctx, unsigned char *array, int bit_offset );
#endif // USE_RBIT_TEST

#endif // __cache_h__ 
