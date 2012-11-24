// do:
//
//    generate sha1(out_fd) and attach to out_fd
//    generate x = rabbit gf(28)times lfsr
//    out_fd ^= x;
//

#include "config.h"
#if defined(USE_LIBGCRYPT)
#include <gcrypt.h>
#endif
#include "rabbit.h"
#include "sha1.h"
#include "util.h"
#include "diffuser.h"

extern int trace_flag;

#if 0
/* Add two numbers in a GF(2^8) finite field */
static uint8_t gadd(uint8_t a, uint8_t b) {
        return a ^ b;
}
 
/* Subtract two numbers in a GF(2^8) finite field */
static uint8_t gsub(uint8_t a, uint8_t b) {
        return a ^ b;
}
#endif
 
/* Multiply two numbers in the GF(2^8) finite field defined 
 * by the polynomial x^8 + x^4 + x^3 + x + 1 */
static uint8_t gmul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        uint8_t counter;
        uint8_t hi_bit_set;
        for (counter = 0; counter < 8; counter++) {
                if (b & 1) 
                        p ^= a;
                hi_bit_set = (a & 0x80);
                a <<= 1;
                if (hi_bit_set) 
                        a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
                b >>= 1;
        }
        return p;
}

// gen
void wabbit_gen ( unsigned char *key, unsigned int fd )
{
  unsigned char salt [ 8 ];
  unsigned char *src,*dst;
  int key_len = strlen(key);
  gpg_error_t sts;
  int rounds = 8 + key_len;
  // this poly has a size of 10^50
  int poly_array[5] = {168,166,153,151,-1};
  int i;
  unsigned int sha1_digest [ 5 ];
  unsigned char W [ 320 ];
  unsigned char sha1_input [ 512/8 ];
  struct {
    unsigned char rabbit_key [ 128/8 ];
    unsigned char rabbit_vec [ 64/8 ];
    BS bs;
  } x[1];
  ECRYPT_ctx ecrypt_ctx;
  struct stat fd_sb;
  size_t cnt_remain;
  size_t cnt;

  // init sha1
  sha_init(sha1_digest);
  memset(W,0,sizeof(W));

  // generate sha1 from fd
  mf_fstat(fd,&fd_sb);
  rw(mf_lseek,fd,0,SEEK_SET);
  cnt_remain = fd_sb.st_size;

  // walk entire file
  while ( cnt_remain > 0 ) {
    cnt = min(cnt_remain,sizeof(sha1_input));
    memset(sha1_input,0,sizeof(sha1_input));
    rw(mf_read,fd,sha1_input,cnt);
    sha_transform(sha1_digest,
		  sha1_input,
		  (unsigned int *)W);
    // onward
    cnt_remain -= cnt;
  }

  {
    struct stat sb;
    off_t small_entropy_start;

    rw(mf_lseek,fd,0,SEEK_END);
    mf_fstat(fd,&sb);
    small_entropy_start = sb.st_size;

    // write digest to file
    rw(mf_write,fd,(char *)sha1_digest,sizeof(sha1_digest));

    // diffuse
    diffuse_diffuse ( key, fd, small_entropy_start );
  }

  //
  // prepare to encrypt fd
  //

  // get salt from key
  dst = salt;
  src = key;
  for ( i = 0 ; i < sizeof(salt) ; i++ ) {
    dst [ i ] = key [ i % key_len ];
  }
  // get key bits for rabbit and lfsr
  sts = gcry_kdf_derive ( key,key_len,
			  GCRY_KDF_ITERSALTED_S2K,GCRY_MD_SHA512,
			  salt, sizeof(salt),
			  rounds, // rounds
			  sizeof(x),x );
  // set iv, key for rabbit
  memset(&ecrypt_ctx,0,sizeof(ECRYPT_ctx));
  ECRYPT_keysetup( &ecrypt_ctx,
		   x[0].rabbit_key, 128,
		   64 );
  ECRYPT_ivsetup( &ecrypt_ctx,
		  x[0].rabbit_vec);

  //
  // encrypt fd
  //
  cnt_remain = fd_sb.st_size + sizeof(sha1_digest);
  rw(mf_lseek,fd,0,SEEK_SET);

  while ( cnt_remain > 0 ) {
    unsigned char file_dat [ 16 ];
    unsigned char lfsr_dat [ 16 ];
    unsigned char rabbit_dat [ 16 ];

    cnt = min ( sizeof(file_dat), cnt_remain );

    // read file
    rw(mf_read,fd,file_dat,cnt);

    for ( i = 0 ; i < cnt ; i++ ) {
      // get 'good' lfsr bits
      while ( 1 ) {
	lfsr_dat [ i ] = get_lfsr_bits ( 8, &x[0].bs, poly_array );
	if ( 0 == lfsr_dat [ i ] || 0xff == lfsr_dat [ i ] )
	  continue;
	break;
      }
    }

    /* Generate rabbit keystream */
    ECRYPT_keystream_bytes(&ecrypt_ctx,
			   rabbit_dat,
			   sizeof(rabbit_dat) );

    for ( i = 0 ; i < cnt ; i++ ) {
      // x^ mul ( lfsr, rabbit )
      file_dat [ i ] ^= gmul ( lfsr_dat[i], rabbit_dat[i] );
    }

    // write output
    rw(mf_lseek,fd,-cnt,SEEK_CUR);
    rw(mf_write,fd,file_dat,cnt);

    // onward
    cnt_remain -= cnt;
  }

  // done
}

// chk, return TRUE if ok, else FALSE
int wabbit_chk ( unsigned char *key, unsigned int fd_in, unsigned int fd_out )
{
  unsigned char salt [ 8 ];
  unsigned char *src,*dst;
  int key_len = strlen(key);
  gpg_error_t sts;
  int rounds = 8 + key_len;
  // this poly has a size of 10^50
  int poly_array[5] = {168,166,153,151,-1};
  int i;
  unsigned int sha1_digest [ 5 ];
  unsigned int sha1_file_digest [ 5 ];
  unsigned char W [ 320 ];
  unsigned char sha1_input [ 512/8 ];
  struct {
    unsigned char rabbit_key [ 16 ];
    unsigned char rabbit_vec [ 8 ];
    BS bs;
  } x[1];
  ECRYPT_ctx ecrypt_ctx;
  struct stat fd_sb;
  size_t cnt_remain;
  size_t cnt;

  //
  // prepare to decrypt fd
  //

  // get salt from key
  dst = salt;
  src = key;
  for ( i = 0 ; i < sizeof(salt) ; i++ ) {
    dst [ i ] = key [ i % key_len ];
  }
  // get key bits for rabbit and lfsr
  sts = gcry_kdf_derive ( key,key_len,
			  GCRY_KDF_ITERSALTED_S2K,GCRY_MD_SHA512,
			  salt, sizeof(salt),
			  rounds, // rounds
			  sizeof(x),x );
  // set iv, key for rabbit
  memset(&ecrypt_ctx,0,sizeof(ECRYPT_ctx));
  ECRYPT_keysetup( &ecrypt_ctx,
		   x[0].rabbit_key, 128,
		   64 );
  ECRYPT_ivsetup( &ecrypt_ctx,
		  x[0].rabbit_vec);

  //
  // decrypt fd
  //
  mf_fstat(fd_in,&fd_sb);
  cnt_remain = fd_sb.st_size;
  rw(mf_lseek,fd_in,0,SEEK_SET);

#if 0
  printf("%s: (decode) cnt_remain = %d\n",
	 __FUNCTION__,cnt_remain);
#endif

  while ( cnt_remain > 0 ) {
    unsigned char file_dat [ 16 ];
    unsigned char lfsr_dat [ 16 ];
    unsigned char rabbit_dat [ 16 ];

    cnt = min ( sizeof(file_dat), cnt_remain );

    //printf("%s: cnt = %d\n",__FUNCTION__,cnt);

    for ( i = 0 ; i < cnt; i++ ) {
      // get 'good' lfsr bits
      while ( 1 ) {
	lfsr_dat [ i ] = get_lfsr_bits ( 8, &x[0].bs, poly_array );
	if ( 0 == lfsr_dat [ i ] || 0xff == lfsr_dat [ i ] )
	  continue;
	break;
      }
    }

    /* Generate rabbit keystream */
    ECRYPT_keystream_bytes(&ecrypt_ctx,
			   rabbit_dat,
			   sizeof(rabbit_dat) );

    // read file
    rw(mf_read,fd_in,file_dat,cnt);
    // xor
    for ( i = 0 ; i < cnt ; i++ ) {
      // x^ mul ( lfsr, rabbit )
      file_dat [ i ] ^= gmul ( lfsr_dat[i], rabbit_dat[i] );
    }

    // write
    rw(mf_write,fd_out,file_dat,cnt);

    // onward
    cnt_remain -= cnt;
  }

  {
    struct stat sb;
    off_t small_entropy_start;

    mf_fstat(fd_out,&sb);
    small_entropy_start = sb.st_size - 20;

    // un_diffuse
    diffuse_un_diffuse ( key, fd_out, small_entropy_start );
  }

#if 0
  {
    char abuf [ AES_BLOCK_SIZE ];
    mf_lseek(fd_out,0,SEEK_SET);
    rw(mf_read,fd_out,abuf,AES_BLOCK_SIZE);
    
    printf("%s:%d: first block after wabbit decrypt\n",
	   __FUNCTION__,__LINE__);
    debug_show_block ( abuf, AES_BLOCK_SIZE );
  }
#endif

  //printf("%s: now compute sha1\n",__FUNCTION__);

  //
  // now, compute sha1
  //

  // init sha1
  sha_init(sha1_digest);
  memset(W,0,sizeof(W));

  // generate sha1 from fd
  mf_fstat(fd_out,&fd_sb);
  rw(mf_lseek,fd_out,0,SEEK_SET);
  cnt_remain = fd_sb.st_size - sizeof(sha1_digest);

  //printf("%s: (sha1) cnt_remain = %d\n",__FUNCTION__,cnt_remain);

  // walk entire file
  while ( cnt_remain > 0 ) {
    cnt = min(cnt_remain,sizeof(sha1_input));
    memset(sha1_input,0,sizeof(sha1_input));
    rw(mf_read,fd_out,sha1_input,cnt);
    sha_transform(sha1_digest,
		  sha1_input,
		  (unsigned int *)W);
    // onward
    cnt_remain -= cnt;
  }

  //printf("%s: now compare digest\n",__FUNCTION__);

  // get file digest
  rw(mf_read,fd_out,(char *)sha1_file_digest,sizeof(sha1_file_digest));

  // compare and return
  sts = 0 == memcmp( sha1_digest, sha1_file_digest, sizeof(sha1_digest) ) ? 1 : 0;

  if ( !sts ) {
    int i;

    printf("%s: Error, sha1 digest did not compare\n",__FUNCTION__);

    printf("computed - ");
    for ( i = 0 ; i < 20 ; i++ ) {
      printf("0x%02x ",sha1_digest[i]&0xff);
    }
    printf("\n");

    printf("actual   - ");
    for ( i = 0 ; i < 20 ; i++ ) {
      printf("0x%02x ",sha1_file_digest[i]&0xff);
    }
    printf("\n");

    exit(0);
  }

  return sts;
}
