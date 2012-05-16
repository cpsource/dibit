// get bits from key_file.dat

#include "config.h"

#include "key_file.h"

extern int trace_flag;

#define min(a,b) ({	\
      int v = a; \
      if ( b < v ) v = b; \
      v; })

// truncate a file
// specifically, we close a hole in a file created when keys were extracted
void key_file_truncate ( PGM_CTX *pgm_ctx, off_t start_hole, int hole_size )
{
  char *buf    = alloca ( hole_size );
  off_t target = start_hole;
  off_t src    = start_hole + hole_size;
  struct stat sb;
  int sts;
  int cnt;
  int chunks_moved = 0;

  if ( 1 || trace_flag > 1 ) {
    printf("%s: Closing %d byte hole in key_file.dat at 0x%x.\n",
	   __FUNCTION__,
	   hole_size,
	   (int)start_hole);
  }

  if ( pgm_ctx->dibit_n_flag ) {
    printf("%s: Error, n_flag must not be set\n",__FUNCTION__);
    exit(0);
  }

  sts = fstat(key_file_fd(pgm_ctx),&sb);
  if ( sts < 0 ) {
    printf("%s: fstat failed on fd %d, errno = %d, strerror = <%s>\n",
	   __FUNCTION__,
	   key_file_fd(pgm_ctx),
	   errno, strerror(errno));
    return;
  }

  //
  //           (hole)
  //  xxxxxx000000000000xxxxxx <eof>
  //        ^           ^
  //      target       src
  //

#if 1

  // faster algorithm - grab from the tail end of the file,
  // then just patch the hole.
  cnt = min ( hole_size, sb.st_size - src );

  // get src -> buf;
  rw(lseek,key_file_fd(pgm_ctx),(off_t)cnt,SEEK_END);
  rw(read ,key_file_fd(pgm_ctx),buf,cnt);

  // write to target
  rw(lseek,key_file_fd(pgm_ctx),target,SEEK_SET);
  rw(write,key_file_fd(pgm_ctx),buf,cnt);

  // onward
  chunks_moved = 1;

#else

  while ( src < sb.st_size ) {
    cnt = min ( hole_size, sb.st_size - src );
    if ( cnt <= 0 ) break;

    // get src -> buf;
    rw(lseek,key_file_fd(pgm_ctx),src,SEEK_SET);
    rw(read ,key_file_fd(pgm_ctx),buf,cnt);

    // write to target
    rw(lseek,key_file_fd(pgm_ctx),target,SEEK_SET);
    rw(write,key_file_fd(pgm_ctx),buf,cnt);

    // onward
    target += cnt;
    src    += cnt;
    chunks_moved += 1;
  }

#endif

  // zero last part of file
  // The Paranoid Refrain: Just because you think someone is watching you, doesn't mean they aren't.
  memset(buf,0,hole_size);
  rw(lseek,key_file_fd(pgm_ctx),hole_size, SEEK_END);
  rw(write,key_file_fd(pgm_ctx),buf,hole_size);

  // truncate file by hole_size
  target = sb.st_size - hole_size;
  sts = ftruncate(key_file_fd(pgm_ctx),target);
  if ( sts < 0 ) {
    printf("%s: ftruncate failed on fd %d, errno = %d, strerror = <%s>\n",
	   __FUNCTION__,
	   key_file_fd(pgm_ctx),
	   errno, strerror(errno));
  }

  // update sb
  pgm_ctx->key_file_sb_valid = 1;
  fstat(key_file_fd(pgm_ctx),&pgm_ctx->key_file_sb);

  // done

  if ( trace_flag > 1 ) {
    printf("%s: returning, chunks moved = %d\n",__FUNCTION__,chunks_moved);
  }
}

// saves a byte in pgm_ctx cache so that later, it can be written out
// to key_database.db
static void save_off ( PGM_CTX *pgm_ctx, unsigned char c )
{
  if ( pgm_ctx->dibit_n_flag ) {
    printf("%s: Error, n_flag must not be set\n",__FUNCTION__);
    exit(0);
  }

  // save off for later
  if ( pgm_ctx->key_file_saved_bits_remain > 0 ) {
    pgm_ctx->key_file_saved_bits [ pgm_ctx->key_file_saved_bits_cnt ] = c;
    
    pgm_ctx->key_file_saved_bits_remain -= 1;
    pgm_ctx->key_file_saved_bits_cnt    += 1;
  } else {
    printf("%s: Error, key_file_saved_bits overflow, increase KEY_FILE_SAVED_BITS_MAX and recompile. (%d)\n",
	   __FUNCTION__,
	   pgm_ctx->key_file_saved_bits_cnt);
    exit(0);
  }
}

// pull next byte from saved
static unsigned char pull_saved ( PGM_CTX *pgm_ctx )
{
  unsigned char c;

  if ( pgm_ctx->dibit_n_flag ) {
    printf("%s: Error, n_flag must not be set\n",__FUNCTION__);
    exit(0);
  }

#if 0
  printf("%s: pgm_ctx->key_file_saved_bits_idx = %d, pgm_ctx->key_file_saved_bits_cnt = %d\n",
	 __FUNCTION__,
	 pgm_ctx->key_file_saved_bits_idx,
	 pgm_ctx->key_file_saved_bits_cnt);
#endif

  if ( pgm_ctx->key_file_saved_bits_idx >= pgm_ctx->key_file_saved_bits_cnt ) {
    printf("%s: Error, no more key bytes saved in cache\n",__FUNCTION__);
    exit(0);
  }

  c = pgm_ctx->key_file_saved_bits [ pgm_ctx->key_file_saved_bits_idx++ ];

#if 0
  printf("%s: pulling 0x%02x\n",
	 __FUNCTION__,
	 c & 0xff );
#endif

  return c;
}

// read one key file byte
static unsigned char read_one_key_file_byte ( PGM_CTX *pgm_ctx )
{
  unsigned char res = 0;

  if ( pgm_ctx->dibit_n_flag ) {
    printf("%s: Error, n_flag must not be set\n",__FUNCTION__);
    exit(0);
  }

  // -a and -d ???
  if ( pgm_ctx->dibit_a_flag && pgm_ctx->dibit_d_flag ) {
    // yes, get from saved
    res = pull_saved(pgm_ctx);
    pgm_ctx->key_file_offset = (pgm_ctx->key_file_offset + 1) % ( pgm_ctx->key_file_sb.st_size - 1 );
  } else {
    // no, get from file
    do {
      rw(lseek,pgm_ctx->key_file_fd,pgm_ctx->key_file_offset,SEEK_SET);
      rw(read , key_file_fd(pgm_ctx) , &res, 1);
      pgm_ctx->key_file_offset = (pgm_ctx->key_file_offset + 1) % ( pgm_ctx->key_file_sb.st_size - 1 );
    } while ( res == 0 || res == -1 );
    // save what we ended up with
    save_off(pgm_ctx,res);
  }

  if ( trace_flag > 1 ) {
    printf("%s: read 0x%02x, pgm_ctx->key_file_offset = %d\n",
	   __FUNCTION__,
	   res & 0xff,
	   pgm_ctx->key_file_offset);
  }

  // done
  return res;
}

// read from key file
void key_file_read ( PGM_CTX *pgm_ctx, unsigned char *target, int cnt )
{
  int i;

  if ( pgm_ctx->dibit_n_flag ) {
    printf("%s: Error, n_flag must not be set\n",__FUNCTION__);
    exit(0);
  }

  //printf("%s: entry, cnt = %d\n",__FUNCTION__,cnt);

  for ( i = 0 ; i < cnt ; i++ ) {
    target[i] = read_one_key_file_byte ( pgm_ctx );
  }
}

// init
void key_file_init ( PGM_CTX *pgm_ctx, int off /* offset into file to start reading */, int n_flag )
{
  char *dibit_base;
  int mode = O_RDONLY;
  int sts;

  if ( pgm_ctx->dibit_n_flag ) {
    printf("%s: Error, n_flag must not be set\n",__FUNCTION__);
    exit(0);
  }

  //printf("%s: entry\n",__FUNCTION__);

  pgm_ctx->key_file_offset            = off;
  pgm_ctx->key_file_bit               = 0;
  pgm_ctx->key_file_saved_bits_cnt    = 0;
  pgm_ctx->key_file_saved_bits_remain = sizeof(pgm_ctx->key_file_saved_bits);

  if ( n_flag ) return;

  //  -a and encode ???
  if ( pgm_ctx->dibit_a_flag && !pgm_ctx->dibit_d_flag ) {
    // yes, we will need to write the file later
    mode = O_RDWR;
  }

  if ( -1 == pgm_ctx->key_file_fd ) {
    // figure out where in file to grab
    pgm_ctx->key_file_fd = open ( KEY_FILE_NAME , mode);
    if ( pgm_ctx->key_file_fd < 0 && (dibit_base = getenv("DIBIT_BASE")) != NULL ) {
      char key_file_name [ 256 ];
      sprintf( key_file_name, "%s/%s", dibit_base, KEY_FILE_NAME );
      pgm_ctx->key_file_fd = open ( key_file_name , mode );
    }
  }

  sts = fstat( pgm_ctx->key_file_fd , &pgm_ctx->key_file_sb );
  if ( sts < 0 ) {
    printf("%s: Error, stat failed for key_file.dat\n",
	   __FUNCTION__);
    exit(0);
  }
  if ( sts >= 0 ) pgm_ctx->key_file_sb_valid = 1;

  // zero any cache
  pgm_ctx->key_file_prev_offset = -1;
}

// return TRUE if valid
int key_file_valid ( PGM_CTX *pgm_ctx )
{
  return pgm_ctx->key_file_fd != -1 ? 1 : 0;
}

// return the key_file fd
int key_file_fd ( PGM_CTX *pgm_ctx )
{
  return pgm_ctx->key_file_fd;
}

// adjust offset
void key_file_adjust_offset ( PGM_CTX *pgm_ctx, int delta )
{
  pgm_ctx->key_file_offset += delta;
}

#if 0
// read one bit from key_file.dat
static unsigned int key_file_one_bit ( PGM_CTX *pgm_ctx )
{
  unsigned int res = 0;

  if ( pgm_ctx->dibit_n_flag ) {
    printf("%s: Error, n_flag must not be set\n",__FUNCTION__);
    exit(0);
  }

  // is cache invalid ???
  if ( pgm_ctx->key_file_prev_offset != pgm_ctx->key_file_offset ) {
    // yes
    pgm_ctx->key_file_dat = read_one_key_file_byte ( pgm_ctx );
    pgm_ctx->key_file_prev_offset = pgm_ctx->key_file_offset;
  }

  // get the bit
  res = pgm_ctx->key_file_dat & (1<<pgm_ctx->key_file_bit) ? 1 : 0;

  // update the bit
  pgm_ctx->key_file_bit += 1;
  if ( pgm_ctx->key_file_bit > 7 ) {
    // set next bit to 0
    pgm_ctx->key_file_bit = 0;
    // invalidate cache
    pgm_ctx->key_file_prev_offset = -1;
  }

  // return
  return res;
}
#endif

// read multi bit from key_file.dat
unsigned int key_file_multi_bit ( PGM_CTX *pgm_ctx, int cnt )
{
  unsigned int res = 0;
  //int i;

  if ( pgm_ctx->dibit_n_flag ) {
    printf("%s: Error, n_flag must not be set\n",__FUNCTION__);
    exit(0);
  }

  if ( !(cnt%8) ) {
    //static int z = 0;

    key_file_read ( pgm_ctx, (unsigned char *)&res, cnt/8 );

#if 0
    printf("%s: 0x%08x, z = %d\n",
	   __FUNCTION__,
	   res,
	   z++);
#endif

    return res;
  }

  printf("%s: trying for %d bits\n",
	 __FUNCTION__,
	 cnt);
  exit(0);

#if 0
  for ( i = 0 ; i < cnt ; i++ ) {
    res |= (key_file_one_bit(pgm_ctx) << i);
  }
#endif

  return res;
}

// show next free offset
void key_file_show_next_free ( PGM_CTX *pgm_ctx )
{
  printf("%s: next free key_file location 0x%x (%d)\n",
	 __FUNCTION__,
	 pgm_ctx->key_file_offset+1,
	 pgm_ctx->key_file_offset+1);
}

// close
void key_file_close ( PGM_CTX *pgm_ctx )
{
  if ( -1 != pgm_ctx->key_file_fd ) {
    close ( pgm_ctx->key_file_fd );
    pgm_ctx->key_file_fd = -1;
  }
}
