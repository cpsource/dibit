#ifndef __key_file_h__
#define __key_file_h__

// init
void key_file_init ( PGM_CTX *pgm_ctx, int off /* offset into file to start reading */, int n_flag );

// return TRUE if valid
int key_file_valid ( PGM_CTX *pgm_ctx );

// return the key_file fd
int key_file_fd ( PGM_CTX *pgm_ctx );

// adjust offset
void key_file_adjust_offset ( PGM_CTX *pgm_ctx, int delta );

// read multi bit from key_file.dat
unsigned int key_file_multi_bit ( PGM_CTX *pgm_ctx, int cnt );

// show next free offset
void key_file_show_next_free ( PGM_CTX *pgm_ctx );

// close
void key_file_close ( PGM_CTX *pgm_ctx );

// read from key file
void key_file_read ( PGM_CTX *pgm_ctx, unsigned char *target, int cnt );

// truncate a file
// specifically, we close a hole in a file created when keys were extracted
void key_file_truncate ( PGM_CTX *pgm_ctx, off_t start_hole, int hole_size );

#endif // __key_file_h__
