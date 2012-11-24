// diffuse a small amount of entropy into a large pool

#include "config.h"
#include "util.h"
#include "diffuser.h"
#if defined(USE_LIBGCRYPT)
#include <gcrypt.h>
#endif

extern int trace_flag;

// get rbit
// it's just an array that we fill in as we go
// we return the bit # where we found it free
static int get_local_rbit ( unsigned char *array, int bitno )
{
  int off = 0;
  int bit = 0;
  int i_bitno = 0;
  int bit_mask;
  int ret = 0;

  while ( 1 ) {

    bit_mask   = 1<<(bit);

    if ( !(array[off]&bit_mask) ) {
      // count
      if ( i_bitno == bitno ) {
	// found
	ret = off*8 + bit;
	array[off] |= bit_mask;
#if 0
	printf("%s: array[%5d ] = 0x%02x, ret = %d\n",
	       __FUNCTION__,
	       off,
	       array[off],
	       ret);
#endif
	break;
      }
      i_bitno += 1;
    }
    bit += 1;
    if ( bit > 7 ) {
      bit = 0;
      off += 1;
    }
  } // while

  return ret;
}

// get dibit
static int get_local_dibit ( unsigned char *array, int bitno )
{
  int off = 0;
  int bit = 0;
  int i_bitno = 0;
  int bit_mask;
  int dibit_mask;
  int ret = 0;

  while ( 1 ) {

    bit_mask   = 1<<(bit*2);
    dibit_mask = 1<<(bit*2 + 1);
    if ( !(array[off]&dibit_mask) ) {
      // count
      if ( i_bitno == bitno ) {
	// found
	ret = array[off]&bit_mask ? 1 : 0;
	array[off] |= dibit_mask;

#if defined(CP_TRACE)
	  printf("%s: found bit, array[%d] = 0x%02x, bit_mask = 0x%02x, ret = %d\n",
		 __FUNCTION__,
		 off,array[off]&0xff,bit_mask,ret);
#endif

	break;
      }
      i_bitno += 1;
    }
    bit += 1;
    if ( bit > 3 ) {
      bit = 0;
      off += 1;
    }
  } // while

  return ret;
}

// check for duplicate addresses in large
int chk_dups ( off_t off, off_t *dups, int *dups_idx )
{
  int i;

  for ( i = 0 ; i < *dups_idx ; i++ ) {
    if ( dups[i] == off ) {
      // found
      if ( trace_flag > 1 ) printf("%s: dup found = %d, i = %d\n",__FUNCTION__,(int)off,i);
      return 1;
    }
  }

  // add and update index

  //printf("%s: writing dups at %d\n",__FUNCTION__,*dups_idx);

  dups[*dups_idx] = off;
  *dups_idx += 1;

  // not found
  return 0;
}

// diffuse
void diffuse_diffuse ( char *key, unsigned int fd, off_t small_entropy_start )
{
  struct stat sb;
  off_t large_start = 0;
  off_t large_end = small_entropy_start - 1;
  off_t small_start = small_entropy_start;
  off_t small_end;
  unsigned char *small_dibit; // hold small dibit arrary for processing
  unsigned char *small;       // hold small from disk
  unsigned char *small_rbit;  // hold small rbit array
  unsigned int small_cnt_remaining;
  unsigned int large_cnt_remaining;
  // this poly has a size of 10^50
  int poly_array[5] = {166,165,128,127,-1};
  BS bs;
  unsigned char salt [ 8 ];
  gpg_error_t sts;
  int dups_idx;
  off_t *dups;

  // get pools start and end
  mf_fstat(fd,&sb);
  small_end = sb.st_size - 1;

  // get bits remaining in small
  small_cnt_remaining = (small_end - small_start + 1) * 8;
  large_cnt_remaining = (large_end - large_start + 1) * 8;

  // build dibit array of small
  small_dibit = (unsigned char *)alloca ( (small_end - small_start + 1)*2 );
  assert(small_dibit!=NULL);
  memset(small_dibit,0,(small_end - small_start + 1)*2);

  small = (unsigned char *)alloca ( small_end - small_start + 1 );
  assert(small!=NULL);
  rw(mf_lseek,fd,small_entropy_start,SEEK_SET);
  rw(mf_read,fd,small,small_end - small_start + 1);

  small_rbit = (unsigned char *)alloca ( small_end - small_start + 1 );
  assert(small_rbit!=NULL);
  memset(small_rbit,0,small_end - small_start + 1);

  dups = (off_t *)malloc ( (small_end - small_start + 1)*8*sizeof(off_t) );
  assert(dups!=NULL);
  dups_idx = 0;
  memset(dups,0,(small_end - small_start + 1)*8*sizeof(off_t));

  {
    int i;
    for ( i = 0 ; i < small_cnt_remaining ; i++ ) {
      set_dibit ( small_dibit, i, get_bit ( small, i ));
    }
    // zero so we can store results here later
    memset(small,0,small_end - small_start + 1);
  }

  // get salt from key
  {
    int i;
    unsigned char *src,*dst;
    int key_len = strlen(key);

    memset(salt,0xaa,sizeof(salt));
    dst = salt;
    src = key;
    for ( i = 0 ; i < sizeof(salt) + sizeof(salt) ; i++ ) {
      // set
      dst [ i % sizeof(salt)  ] ^= key [ i % key_len ];
      // rotate left
      if ( 0x80 & dst [ i % sizeof(salt)  ] ) {
	dst [ i % sizeof(salt)  ] = (dst [ i % sizeof(salt)  ] << 1) | 1;
      } else {
	dst [ i % sizeof(salt)  ] <<= 1;
      }
    }
  }

  // get key bits for lfsr
  {
    int rounds = 17;

    sts = gcry_kdf_derive ( key,strlen(key),
			    GCRY_KDF_ITERSALTED_S2K,GCRY_MD_SHA512,
			    salt, sizeof(salt),
			    rounds, // rounds
			    sizeof(BS),&bs );
  }

  // run lfsr a bit
  {
    int i;

    i = 257 + strlen(key);
    while ( i-- >0 ) {
      get_lfsr_bits ( 8, &bs, poly_array);
    }
  }

  // diffuse
  while ( small_cnt_remaining ) {
    unsigned int big_bit;
    unsigned int small_bit_in,small_bit_out;
    unsigned int flipper_a,flipper_b;

    off_t big_off;
    int big_bit_no;
    unsigned char big_dat;
    int big_bit_val;
    int place_in_small;
    int small_bit_val;

    //printf("%s: small_cnt_remaining = %d\n",__FUNCTION__,small_cnt_remaining);

    // get three values
    do {
      big_bit       = get_lfsr_bits ( 31, &bs, poly_array) % large_cnt_remaining;
    } while ( chk_dups ( big_bit, dups, &dups_idx ) );

    small_bit_in  = get_lfsr_bits ( 15, &bs, poly_array) % small_cnt_remaining;
    small_bit_out = get_lfsr_bits ( 15, &bs, poly_array) % small_cnt_remaining;
    flipper_a     = get_lfsr_bits ( 1 , &bs, poly_array);
    flipper_b     = get_lfsr_bits ( 1 , &bs, poly_array);

    // get big bit into memory
    big_off = big_bit / 8;
    big_bit_no = big_bit % 8;

    rw(mf_lseek,fd,big_off,SEEK_SET);
    rw(mf_read,fd,&big_dat,1);

    big_bit_val   = (1<<big_bit_no) & big_dat ? 1 : 0;

    if ( trace_flag > 1 )
      printf("%s: small_cnt_remaining = %5d, big_off = %5d, big_bit_no = %d\n",
	     __FUNCTION__,
	     small_cnt_remaining,
	     (int)big_off,
	     (int)big_bit_no);

    small_bit_val = get_local_dibit ( small_dibit, small_bit_in );

    // small -> big_dat
    clr_bit(&big_dat,big_bit_no);
    set_bit (&big_dat,big_bit_no,small_bit_val ^ flipper_a );

    // big -> small
    place_in_small = get_local_rbit ( small_rbit, small_bit_out );
    set_bit ( small, place_in_small, big_bit_val ^ flipper_b );

    // write big bit back onto disk
    rw(mf_lseek,fd,-1,SEEK_CUR);
    rw(mf_write,fd,&big_dat,1);

    // onward
    small_cnt_remaining -= 1;
  }

  // write small back onto disk
  rw(mf_lseek,fd,small_entropy_start,SEEK_SET);
  rw(mf_write,fd,small,small_end - small_start + 1);

  // cleanup
  free(dups);

  // done
}

// un_diffuse
void diffuse_un_diffuse ( char *key, unsigned int fd, off_t small_entropy_start )
{
  struct stat sb;
  off_t large_start = 0;
  off_t large_end = small_entropy_start - 1;
  off_t small_start = small_entropy_start;
  off_t small_end;
  unsigned char *small_dibit; // hold small dibit arrary for processing
  unsigned char *small;       // hold small from disk
  unsigned char *small_rbit;  // hold small rbit array
  unsigned int small_cnt_remaining;
  unsigned int large_cnt_remaining;
  // this poly has a size of 10^50
  int poly_array[5] = {166,165,128,127,-1};
  BS bs;
  unsigned char salt [ 8 ];
  gpg_error_t sts;
  off_t *dups;
  int dups_idx;

  // get pools start and end
  mf_fstat(fd,&sb);
  small_end = sb.st_size - 1;

  // get bits remaining in small
  small_cnt_remaining = (small_end - small_start + 1) * 8;
  large_cnt_remaining = (large_end - large_start + 1) * 8;

  // build dibit array of small
  small_dibit = (unsigned char *)alloca ( (small_end - small_start + 1)*2 );
  assert(small_dibit!=NULL);
  memset(small_dibit,0,(small_end - small_start + 1)*2);

  small = (unsigned char *)alloca ( small_end - small_start + 1 );
  assert(small!=NULL);
  rw(mf_lseek,fd,small_entropy_start,SEEK_SET);
  rw(mf_read,fd,small,small_end - small_start + 1);

  small_rbit = (unsigned char *)alloca ( small_end - small_start + 1 );
  assert(small_rbit!=NULL);
  memset(small_rbit,0,small_end - small_start + 1);

  dups = (off_t *)malloc ( (small_end - small_start + 1)*8*sizeof(off_t) );
  assert(dups!=NULL);
  dups_idx = 0;
  memset(dups,0,(small_end - small_start + 1)*8*sizeof(off_t));

  {
    int i;
    for ( i = 0 ; i < small_cnt_remaining ; i++ ) {
      set_dibit ( small_dibit, i, get_bit ( small, i ));
    }
    // zero so we can store results here
    memset(small,0,small_end - small_start + 1);
  }

  // get salt from key
  {
    int i;
    unsigned char *src,*dst;
    int key_len = strlen(key);

    memset(salt,0xaa,sizeof(salt));
    dst = salt;
    src = key;
    for ( i = 0 ; i < sizeof(salt) + sizeof(salt) ; i++ ) {
      // set
      dst [ i % sizeof(salt)  ] ^= key [ i % key_len ];
      // rotate left
      if ( 0x80 & dst [ i % sizeof(salt)  ] ) {
	dst [ i % sizeof(salt)  ] = (dst [ i % sizeof(salt)  ] << 1) | 1;
      } else {
	dst [ i % sizeof(salt)  ] <<= 1;
      }
    }
  }

  // get key bits for lfsr
  {
    int rounds = 17;

    sts = gcry_kdf_derive ( key,strlen(key),
			    GCRY_KDF_ITERSALTED_S2K,GCRY_MD_SHA512,
			    salt, sizeof(salt),
			    rounds, // rounds
			    sizeof(BS),&bs );
  }

  // run lfsr a bit
  {
    int i;

    i = 257 + strlen(key);
    while ( i-- >0 ) {
      get_lfsr_bits ( 8, &bs, poly_array);
    }
  }

  // un_diffuse
  while ( small_cnt_remaining ) {
    unsigned int big_bit;
    unsigned int small_bit_in,small_bit_out;
    unsigned int flipper_a,flipper_b;

    off_t big_off;
    int big_bit_no;
    unsigned char big_dat;
    int big_bit_val;
    int place_in_small;
    int small_bit_val;

    // get three values
    do {
      big_bit       = get_lfsr_bits ( 31, &bs, poly_array) % large_cnt_remaining;
    } while ( chk_dups ( big_bit, dups, &dups_idx ) );

    small_bit_in  = get_lfsr_bits ( 15, &bs, poly_array) % small_cnt_remaining;
    small_bit_out = get_lfsr_bits ( 15, &bs, poly_array) % small_cnt_remaining;
    flipper_a     = get_lfsr_bits ( 1 , &bs, poly_array);
    flipper_b     = get_lfsr_bits ( 1 , &bs, poly_array);

    // get big bit into memory
    big_off = big_bit / 8;
    big_bit_no = big_bit % 8;

    rw(mf_lseek,fd,big_off,SEEK_SET);
    rw(mf_read,fd,&big_dat,1);

    big_bit_val   = (1<<big_bit_no) & big_dat ? 1 : 0;

    if ( trace_flag > 1 )
      printf("%s: small_cnt_remaining = %5d, big_off = %5d, big_bit_no = %d\n",
	     __FUNCTION__,
	     small_cnt_remaining,
	     (int)big_off,
	     (int)big_bit_no);

    small_bit_val = get_local_dibit ( small_dibit, small_bit_out );

    // small -> big_dat
    clr_bit(&big_dat,big_bit_no);
    set_bit (&big_dat,big_bit_no,small_bit_val ^ flipper_b );

    // big -> small
    place_in_small = get_local_rbit ( small_rbit, small_bit_in );
    set_bit ( small, place_in_small, big_bit_val ^ flipper_a );

    // write big bit back onto disk
    rw(mf_lseek,fd,big_off,SEEK_SET);
    rw(mf_write,fd,&big_dat,1);

    // onward
    small_cnt_remaining -= 1;
  }

  // write small back onto disk
  rw(mf_lseek,fd,small_entropy_start,SEEK_SET);
  rw(mf_write,fd,small,small_end - small_start + 1);

  // cleanup
  free(dups);

  // done
}

#if defined(USE_DIFFUSER_TEST)
// test the diffuser
void diffuser_test ( char *key )
{
  unsigned int fd = mf_open ( "diffuser_test", 0, 256 + 20 );
  int i;
  unsigned char d = 0xff;

  // generate some 0xff's
  for ( i = 0 ; i < 256 ; i++ ) {
    rw(mf_write,fd,&d,1);
  }
  // generate some 0's
  d = 0;
  for ( i = 0 ; i < 20 ; i++ ) {
    rw(mf_write,fd,&d,1);
  }

  // diffuse
  diffuse_diffuse ( key,
		    fd,
		    256 );

  // un_diffuse
  diffuse_un_diffuse ( key,
		       fd,
		       256 );

  // make sure it all came back
  rw(mf_lseek,fd,256,SEEK_SET);
  for ( i = 0 ; i < 20 ; i++ ) {
    rw(mf_read,fd,&d,1);
    if ( d != 0 ) {
      printf("failed at %d, expected 0, received 0x%02x\n",
	     i,d&0xff);
    }
  }

  // check rest for 0's
  rw(mf_lseek,fd,0,SEEK_SET);
  for ( i = 0 ; i < 256 ; i++ ) {
    rw(mf_read,fd,&d,1);
    if ( d != 0xff ) {
      printf("failed at %d, expected 0xff, received 0x%02x\n",
	     i,d&0xff);
    }
  }

  mf_close(fd);
}
#endif
