// manage keys

#include "config.h"
#include "dibit.h"

extern int trace_flag;

// find marker - search backwards for our marker,
// return it's off_t if found or 0 for none
off_t find_marker ( unsigned int fd, off_t call_offset /* start searching here backwards */ )
{
  unsigned char zzz [ AES_BLOCK_SIZE ];
  unsigned char buf [ AES_BLOCK_SIZE ];
  off_t offset = call_offset - AES_BLOCK_SIZE;

  memset(zzz,0,AES_BLOCK_SIZE);

  // a really stupid algorithm
  while ( offset > 0 ) {
    rw(mf_lseek,fd,offset,SEEK_SET);
    rw(mf_read,fd,buf,AES_BLOCK_SIZE);
    if ( 0 == memcmp(zzz,buf,AES_BLOCK_SIZE) ) {
      // found
      break;
    }
    offset -= 1;
  }

  if ( trace_flag ) {
    printf("%s: marker found at offset = %d\n",
	   __FUNCTION__,
	   (int)offset);
  }

  // done
  return offset;
}

// get k_flag from somewhere, based on command line swiches
void key_mgmt_get_key ( PGM_CTX *pgm_ctx,
			char **ck_flag,
			char **ca_flag,
			unsigned int fd_in,
			struct dibit_file_struct_t *dfs,
			char *argv0 )
{
  char *k_flag = *ck_flag;
  char *a_flag = *ca_flag;

  // decode without -a ???
  if ( pgm_ctx->dibit_d_flag && ! pgm_ctx->dibit_a_flag ) {
    return;
  }

  // decode with -a ???
  if ( pgm_ctx->dibit_d_flag && pgm_ctx->dibit_a_flag ) {
    // yes, get k_flag from file
    unsigned int mrec     = mf_open ( "mfrec", 0, 0 );
    unsigned int mrec_out = mf_open ( "mfrec_out", 0, 0);
    struct stat mrec_sb;
    AES_CFB aes_cfb;
    int *data_len,N;
    unsigned int aes_decoded_fd;

    if ( trace_flag > 1 )
      printf("%s:%d: aes_cfb_init with a_flag <%s>\n",
	     __FUNCTION__,__LINE__,a_flag);

    memset(dfs,0,sizeof(struct dibit_file_struct_t));

    //
    // First Job: use aes_cfb decrypt the file with a_flag key
    //
    {
      unsigned char work_buf [ AES_BLOCK_SIZE ];
      off_t blk_cnt;
      off_t blk;

      // get file size
      mf_fstat( fd_in, &mrec_sb );
      // get new temp file
      aes_decoded_fd = mf_open ( "aes_decoded_fd", 0, mrec_sb.st_size );

      blk_cnt = mrec_sb.st_size / AES_BLOCK_SIZE;
      blk     = 0;

      aes_cfb_init ( pgm_ctx,
		     &aes_cfb,
		     a_flag );

      mf_lseek(fd_in, 0, SEEK_SET );

      while ( blk_cnt > 0 ) {
	rw(mf_read,fd_in,work_buf,AES_BLOCK_SIZE);

#if defined(USE_LAST_BLOCK)
	if ( 1 == blk_cnt )
	  last_block_obscure ( work_buf, a_flag );
	else
#endif
	  aes_cfb_decrypt ( pgm_ctx,
			    &aes_cfb,
			    1,
			    work_buf,
			    work_buf);
	
	rw(mf_write,aes_decoded_fd,work_buf,AES_BLOCK_SIZE);
	
	blk_cnt -= 1;
	blk += 1;
      }

      // now putz with fd's

      // assign (Note: You've really got to understand 'c' to understand why this works.)
      mf_assign ( fd_in, aes_decoded_fd );
    }

    //
    // Second Job: skip pad at end of file
    //
    {
      unsigned char t_buf [ AES_BLOCK_SIZE * 2 ];
      unsigned char *t_buf_ptr;

      mf_lseek(fd_in,-1*(AES_BLOCK_SIZE * 2),SEEK_END);
      rw(mf_read,fd_in,t_buf,AES_BLOCK_SIZE * 2);

      dfs->mrec_key_last = mrec_sb.st_size - 1;

      //
      // skip to   xxx10000000000000
      //             ^
      //             |
      //         mrec_key
      //

      t_buf_ptr = &t_buf [ AES_BLOCK_SIZE * 2 ] - 1;
      while ( ! *t_buf_ptr ) {
	// back up
	dfs->mrec_key_last -= 1;
	t_buf_ptr -= 1;
      }
      // skip 1
      if ( *t_buf_ptr != 1 ) {
#if 0
	printf("%s: Error, we backup up,but didn't get a '1', but got 0x%02x instead\n",
	       __FUNCTION__,
	       *t_buf_ptr & 0xff);
	exit(0);
#endif
      } else {
	dfs->mrec_key_last -= 1;
      }
    }

    //
    // Third Job: find the marker
    //
    dfs->marker_offset_start = find_marker ( fd_in, dfs->mrec_key_last );

    //
    // Forth Job: set mrec_key_start and mrec_key_cnt
    //
    dfs->mrec_key_start = dfs->marker_offset_start + AES_BLOCK_SIZE;
    dfs->mrec_key_cnt = dfs->mrec_key_last - dfs->mrec_key_start + 1;

    //
    // Fifth Job: setup dibit_offset_start and dibit_cnt
    //
    dfs->dibit_offset_start = 0;
    dfs->dibit_offset_last = dfs->marker_offset_start - 1;
    dfs->dibit_cnt = dfs->dibit_offset_last - dfs->dibit_offset_start + 1;

    //
    // now, we know the geometry of fd_in
    //

    // make sure we are at the front of our file before proceeding
    rw(mf_lseek,fd_in,0,SEEK_SET);

    //
    // Sixth Job: get mrec key into -> mrec
    //
    {
      //struct stat sb;
      int cnt;

      // get to start of mrec key
      rw(mf_lseek,
	 fd_in,
	 dfs->mrec_key_start,
	 SEEK_SET);
      cnt = dfs->mrec_key_cnt;

      // read it in
      while ( cnt-- > 0 ) {
	unsigned char dat;

	rw(mf_read,fd_in,&dat,1);
	rw(mf_write,mrec,&dat,1);
      }
    }

    // to front of mrec file
    mf_lseek ( mrec, 0, SEEK_SET );
    mf_fstat ( mrec, &mrec_sb );

    //
    // Seventh Job: run mrec through dibit
    //
    {
      int x;
      char lbuf [ 256 ];
      char *c = lbuf;
      int largc;
      char *largv [ 8 ];

      largc = 5;
      
      x = sprintf(c,"%s",argv0);
      largv [ 0 ] = c;
      c += x + 1;
      
      x = sprintf(c,"-n");
      largv [ 1 ] = c;
      c += x + 1;
      
      x = sprintf(c,"-d");
      largv [ 2 ] = c;
      c += x + 1;
      
      x = sprintf(c,"-k");
      largv [ 3 ] = c;
      c += x + 1;
      
      sprintf(c,"%s",a_flag);
      largv [ 4 ] = c;
      
      dibit_main ( largc, largv, mrec, mrec_out );
    }
    
    //
    // Eigth Job: decode mrec_out with aes_cfb
    //

    // to front of file
    mf_lseek ( mrec_out, 0, SEEK_SET );
    mf_fstat ( mrec_out, &mrec_sb );
    //printf("mrec size = %d\n",(int)mrec_sb.st_size);

#if 0
    {
      printf("%s:%d: after dibit decryption, before aes_cfb decryption = %d bytes\n",
	     __FUNCTION__,__LINE__,
	     (int)mrec_sb.st_size);
      debug_show_block ( mf_get_data_ptr(mrec_out),mrec_sb.st_size);
    }
#endif

    aes_cfb_init ( pgm_ctx,
		   &aes_cfb,
		   a_flag );
    
    aes_cfb_decrypt ( pgm_ctx,
		      &aes_cfb,
		      mrec_sb.st_size / 16,
		      mf_get_data_ptr ( mrec_out ),
		      mf_get_data_ptr ( mrec_out ));
    
#if 0
    {
      printf("%s:%d: after dibit aes decryption, mrec_out size = %d bytes\n",
	     __FUNCTION__,__LINE__,
	     (int)mrec_sb.st_size);
      debug_show_block ( mf_get_data_ptr(mrec_out),mrec_sb.st_size);
    }
#endif

    //
    // Ninth Job: parse decoded buffer
    //
    
    if ( k_flag ) {
      free(k_flag);
    }
    k_flag = strdup( mf_get_data_ptr ( mrec_out ) );

#if 0
    // only for test
    if ( strlen(k_flag) > 64 ) {
      printf("%s:%d bad key\n",
	     __FUNCTION__,__LINE__);
      exit(0);
    }
#endif
    
    mf_lseek ( mrec_out, strlen(k_flag) + 1, SEEK_SET );
    data_len = (unsigned int *)mf_get_data_ptr ( mrec_out );
    N = *data_len;
    
    if ( trace_flag > 1 ) printf("key_string = <%s>, N = %d\n",k_flag,N);

    // point to data
    mf_lseek ( mrec_out, 4, SEEK_CUR );
    
    // load data into cache
    memcpy(pgm_ctx->key_file_saved_bits,mf_get_data_ptr(mrec_out),N);
    pgm_ctx->key_file_saved_bits_cnt = N;
    pgm_ctx->key_file_saved_bits_remain = KEY_FILE_SAVED_BITS_MAX - N;
    pgm_ctx->key_file_saved_bits_idx = 0;

#if 0
    {
      printf("%s:%d: data cache is N = %d bytes in size\n",
	     __FUNCTION__,__LINE__,N);
      debug_show_block ( pgm_ctx->key_file_saved_bits, N );
    }
#endif

    //
    // cleanup
    //
    mf_close( mrec );
    mf_close( mrec_out );

    // return k_flag
    *ck_flag = k_flag;

    // done
    return;

  } // if decode with -a ???

  // encode without -a ???
  if ( !pgm_ctx->dibit_d_flag && !pgm_ctx->dibit_a_flag ) {
    // yes, k_flag is ok
    return;
  }

  // encode with -a ???
  if ( !pgm_ctx->dibit_d_flag && pgm_ctx->dibit_a_flag ) {

    // yes
    // we are encoding
    char *x;
    char wbuf [ 256 ];

    if ( !k_flag ) {
      printf("Error, no key provided to encrypt file\b");
      exit(0);
    }

    x = strchr(k_flag,'-');
    if ( x )
      x += 1;
    else
      x = k_flag;

    // adjust sql_next_key_offset to some random location
    {
      union {
	unsigned char m[4];
	unsigned int r;
      } v;

      // read as bytes so we don't get any 0 or ff
      v.m[0] = urandom_pseudo_get_multi_bit ( pgm_ctx, 8);
      v.m[1] = urandom_pseudo_get_multi_bit ( pgm_ctx, 8);
      v.m[2] = urandom_pseudo_get_multi_bit ( pgm_ctx, 8);
      v.m[3] = urandom_pseudo_get_multi_bit ( pgm_ctx, 8);

      // is file big enough ???
      if ( pgm_ctx->key_file_sb.st_size < KEY_FILE_SAVED_BITS_MAX ) {
	printf("%s: Error, key_file.dat is not big enough to proceed. Go get a new bigger one.\n",__FUNCTION__);
	exit(0);
      }

      // jump out to some random place, make sure we have enough remaining
      // tell key_file module
      pgm_ctx->key_file_offset_start = 
	pgm_ctx->key_file_offset =
	v.r % ( pgm_ctx->key_file_sb.st_size - KEY_FILE_SAVED_BITS_MAX );

      // zero any cache
      pgm_ctx->key_file_prev_offset = -1;

    }

    sprintf(wbuf,"0x%x-%s",
	    pgm_ctx->key_file_offset,
	    x);

    if ( k_flag ) {
      free(k_flag);
      k_flag = strdup(wbuf);
    }

    *ck_flag = k_flag;

    printf("M-Key: <%s>\n",k_flag);

    return;
  } // if encode with -a ???

  printf("%s: can't get here\n",__FUNCTION__);
  exit(0);
}
