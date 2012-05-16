#ifndef __pgm_ctx_h__
#define __pgm_ctx_h__

#define KEY_FILE_SAVED_BITS_MAX 8192

struct pgm_ctx_aes_struct_t {
  // aes
  int crypto_register_init_flag;
  int crypto_next_bit; // 0..127
  struct crypto_aes_ctx crypto_aes_ctx;
  unsigned char crypto_aes_key[AES_MAX_KEY_SIZE];
  unsigned char crypto_aes_register_a [ AES_BLOCK_SIZE ];
  unsigned char crypto_aes_register_b [ AES_BLOCK_SIZE ];
  //unsigned char crypto_aes_register_c [ AES_BLOCK_SIZE ];
};

struct top_cell_struct_t;
struct aes_pseudo_struct_t;
struct cache_ctx_t;
struct cell_struct_t;

typedef struct pgm_ctx_struct_t {

  //
  // dibit.c
  //
  int dibit_a_flag;
  int dibit_n_flag;
  int dibit_d_flag;
  int dibit_z_flag;
  int dibit_first_salt_flag;
  // used by nrand48
  unsigned short xsubi [ 3 ];
  // size of cleartext file
  int dibit_st_size;
  struct top_cell_struct_t *top_cell;

  // second and third sources of pseudo-ramdom data
  D_LFSR second_pseudo_random_sequence;
  D_LFSR third_pseudo_random_sequence;
  // controller pseudo-random data
  D_LFSR controller_pseudo_random_sequence;
#if defined(USE_AES)
  // AES binding for controller
  struct aes_pseudo_struct_t *aes_pseudo_controller;
#endif

  // need one of these for cache module
  struct cache_ctx_t *ctx;
#if defined(USE_RBIT_TEST)
  struct cache_ctx_t *rbit_ctx;
#endif

  // aes
  struct pgm_ctx_aes_struct_t pgm_ctx_aes_a;
  struct pgm_ctx_aes_struct_t pgm_ctx_aes_b;

  // keybuf context
  KEYBUF_3 dibit_kb3;
  KEYBUF_3_ITERATOR dibit_kb3_i;

  //
  // key_file.c
  //

  unsigned char key_file_dat;
  int key_file_prev_offset;
  int key_file_sb_valid;
  struct stat key_file_sb;
  int key_file_offset;
  int key_file_offset_start;
  int key_file_bit;
  int key_file_fd;
  // save off key bits we read from key_file.dat for later
  // (if necessary)
  unsigned int key_file_saved_bits_cnt;
  unsigned int key_file_saved_bits_remain;
  unsigned int key_file_saved_bits_idx;
  unsigned char key_file_saved_bits [ KEY_FILE_SAVED_BITS_MAX ];

  //
  // bbs_pseudo.c
  //
  RNDBBS rndbbs;
  // number of bytes to get at once from rndbbs
#define RNDBBS_KEY_CNT 32
  int rndbbs_init_ok; // 1 if rndbbs_data is valid
  int rndbbs_idx;     // 0..RNDBBS_KEY_CNT*8-1
  unsigned char rndbbs_data [ RNDBBS_KEY_CNT ];

  //
  // urandom_pseudo.c
  //
#define URANDOM_PSEUDO_CHUNK 4
  int urandom_fd;
  int urandom_init_ok;
  int urandom_next_bit; // 0 .. (URANDOM_PSEUDO_CHUNK*8)-1
  unsigned char urandom_data [ URANDOM_PSEUDO_CHUNK ];

  //
  // lfsr
  //
  int poly_array_used[MAX_POLY_ARRAY]; // 1 if we've already used that poly

  //
  // cell.c
  //
  // cells are wrapped evenly around a sphere
  //
  struct cell_struct_t *cell_cells;
  int cell_move_x_idx;
  int cell_move_y_idx;

} PGM_CTX;

// create new program context structure
PGM_CTX *pgm_ctx_new ( void );

#endif // __pgm_ctx_h__
