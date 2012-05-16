
//#define CP_TRACE
#define CACHE_TEST

#include "config.h"

#include <getopt.h>
#include "dibit.h"
#include "key_mgmt.h"

extern int trace_flag;

#include "util.c"

// encrypt or decrypt
int dibit_main ( int argc, char *argv[], unsigned int file_in, unsigned int file_out )
{
  struct stat sb;
  unsigned char *ibuf, *dibuf, *obuf;
#if !defined(USE_RBIT_TEST)
  unsigned char *rbuf;
#endif

#if defined(CACHE_TEST)
  //unsigned char *dibuf_tst;
#endif

  int fd_in  = file_in;
  int fd_out = file_out;

  int i;
  int bitcount;
  int rnd, rbit_rnd,dat_rnd;
  int randmod;

  // remaining bytes in cleartext
  int remaining_cleartext;

  // our output file
  char *burried_output_file = NULL;

  char *mkstemp_file = NULL;

  // create new program context
  PGM_CTX *pgm_ctx = pgm_ctx_new ( );

  char *k_flag = NULL;
  char *f_flag = NULL;
  char *a_flag = NULL;

  char *m_key = NULL;

  int saved_trace_flag = trace_flag;

  struct dibit_file_struct_t dfs;

#if 0
  {
    int i;

    for ( i = 0 ; i < argc ; i++ ) {
      printf("argv[%02d] = <%s>\n",
	     i,argv[i]);
    }
  }
#endif

  // need one of these for cache module
  pgm_ctx->ctx = cache_ctx_new ( );
#if defined(USE_RBIT_TEST)
  pgm_ctx->rbit_ctx = cache_ctx_new ( );
#endif

  optind = 1;

  // get arguments from command line
  while ( 1 ) {
    switch ( getopt(argc,argv,"a:nhdzk:f:t:") )
      {
      case 'a':
	pgm_ctx->dibit_a_flag = 1;
	m_key = strdup ( optarg );
	a_flag = strdup ( optarg );
	break;
      case 'n':
	// no key_file.dat
	pgm_ctx->dibit_n_flag = 1;
	break;
	// set trace level
      case 't':
	trace_flag = atoi(optarg);
	break;
      case 'h':
	printf("Usage: %s [-a \"key\"] [-f \"file\"] [-z] [-k \"key string\"] [-d]\n",argv[0]);
	exit(0);
	break;
      case 'f':
	f_flag = strdup ( optarg );
	//printf("%s: f_flag = <%s>\n",__FUNCTION__,f_flag);
	break;
      case 'k':
	k_flag = strdup ( optarg );
	//printf("%s: k_flag = <%s>\n",__FUNCTION__,k_flag);
	break;
      case 'z':
	pgm_ctx->dibit_z_flag = 1;
	break;
      case 'd':
	pgm_ctx->dibit_d_flag = 1;
	break;
      case -1:
	goto getopt_finis;
      }
  }
 getopt_finis:;

  // open cipher/clear text file
  if ( -1 == file_in ) {
    if ( trace_flag > 1 ) printf("%s: opening <%s>\n",__FUNCTION__,f_flag);
    fd_in = mf_open ( f_flag, O_RDONLY, 0xdeadbeef );
  }
  if ( -1 == fd_in ) {
    printf("%s:%d: Error, can't open <%s>, errno = %d, strerror = <%s>\n",
	   __FUNCTION__,__LINE__,
	   f_flag,
	   errno,
	   strerror(errno));
    exit(0);
  }

  // init urandom
  urandom_pseudo_init ( pgm_ctx );

  if ( !pgm_ctx->dibit_n_flag ) {
    // init key file
    // TODO - doesn't have to be done if -m -d
    key_file_init ( pgm_ctx, 0, pgm_ctx->dibit_n_flag );
  }

  // get k_flag from somewhere, based on command line swiches
  key_mgmt_get_key ( pgm_ctx, &k_flag, &a_flag, fd_in, &dfs, argv[0] );

  // init getkey
  if ( trace_flag > 1 ) printf("calling getkey_3 with k_flag = <%s>\n",k_flag);
  getkey_3 ( pgm_ctx, k_flag , &pgm_ctx->dibit_kb3 );
  /* initialize new iterator */
  kb_iterator_new ( &pgm_ctx->dibit_kb3_i, &pgm_ctx->dibit_kb3 );

#if defined(USE_AES)

  // initialize AES 'a', get its key from our primary key of 128 bits
  {
    int i;
    int sts;

    for ( i = 0 ; i < AES_KEYSIZE_128 ; i++ ) {
      pgm_ctx->pgm_ctx_aes_a.crypto_aes_key [ i ] = getNKeyBits_3_iterator ( pgm_ctx, 8, &pgm_ctx->dibit_kb3_i );
    }

    if ( trace_flag > 1 ) printf("calling crypto_aes_set_key\n");

    sts = crypto_aes_set_key( &pgm_ctx->pgm_ctx_aes_a.crypto_aes_ctx,
			      pgm_ctx->pgm_ctx_aes_a.crypto_aes_key, AES_KEYSIZE_128 );
    if ( sts ) {
      printf("%s: Error, crypto_aes_set_key failed with error %d\n",
	     __FUNCTION__,
	     sts);
      exit(0);
    }
  }

  // initialize AES 'b', get its key from our primary key of 128 bits
  {
    int i;
    int sts;

    for ( i = 0 ; i < AES_KEYSIZE_128 ; i++ ) {
      pgm_ctx->pgm_ctx_aes_b.crypto_aes_key [ i ] = getNKeyBits_3_iterator ( pgm_ctx, 8, &pgm_ctx->dibit_kb3_i );
    }

    if ( trace_flag > 1 ) printf("calling crypto_aes_set_key\n");

    sts = crypto_aes_set_key( &pgm_ctx->pgm_ctx_aes_b.crypto_aes_ctx,
			      pgm_ctx->pgm_ctx_aes_b.crypto_aes_key, AES_KEYSIZE_128 );
    if ( sts ) {
      printf("%s: Error, crypto_aes_set_key failed with error %d\n",
	     __FUNCTION__,
	     sts);
      exit(0);
    }
  }

#endif // USE_AES

#if defined(USE_BBS)
  if ( ! pgm_ctx->dibit_n_flag ) {
    // init
    bbs_pseudo_init ( pgm_ctx );
  }
#endif // USE_BBS

  // init cell, and setup a top_cell
  if ( trace_flag > 1 ) printf("calling cell_init\n");
  cell_init(pgm_ctx,&pgm_ctx->dibit_kb3_i);

  if ( trace_flag > 1 ) printf("calling cell_new_top_cell\n");
  pgm_ctx->top_cell = cell_new_top_cell();

  // init lfsr
  if ( trace_flag > 1 ) printf("calling lfsr_init3\n");
  lfsr_init(pgm_ctx);

  if ( trace_flag > 1 ) printf("getting second and thrid pseudo-random sources\n");

  // get controller pseudo-random source
  init_dual_lfsr_from_key ( pgm_ctx,
			    &pgm_ctx->controller_pseudo_random_sequence,
			    &pgm_ctx->dibit_kb3_i );
  // get second pseudo-random source
  init_dual_lfsr_from_key ( pgm_ctx,
			    &pgm_ctx->second_pseudo_random_sequence,
			    &pgm_ctx->dibit_kb3_i );
  // get third pseudo-random source
  init_dual_lfsr_from_key ( pgm_ctx,
			    &pgm_ctx->third_pseudo_random_sequence,
			    &pgm_ctx->dibit_kb3_i );

#if defined(USE_AES)
  pgm_ctx->aes_pseudo_controller = (AES_PSEUDO *)malloc(sizeof(AES_PSEUDO));
  assert(pgm_ctx->aes_pseudo_controller!=NULL);
  memset(pgm_ctx->aes_pseudo_controller,0,sizeof(AES_PSEUDO));

  aes_pseudo_bind ( &pgm_ctx->controller_pseudo_random_sequence,
		    &pgm_ctx->pgm_ctx_aes_a,
		    pgm_ctx->aes_pseudo_controller );

#define GET_PSEUDO_CONTROLLER_BITS(cnt) aes_pseudo_get_multi_bit ( pgm_ctx->aes_pseudo_controller, cnt )

#else

#define GET_PSEUDO_CONTROLLER_BITS(cnt) get_dual_lfsr_bits ( cnt, &pgm_ctx->controller_pseudo_random_sequence )

#endif // USE_AES

  // setup xsubi for Xrand48 
  pgm_ctx->xsubi [ 0 ] = GET_PSEUDO_CONTROLLER_BITS(16);
  pgm_ctx->xsubi [ 1 ] = GET_PSEUDO_CONTROLLER_BITS(16);
  pgm_ctx->xsubi [ 2 ] = GET_PSEUDO_CONTROLLER_BITS(16);

  // make sure we are at the front of our file
  rw(mf_lseek,fd_in,0,SEEK_SET);

  // get remaining_cleartext/ciphertext count
  if (pgm_ctx->dibit_d_flag && pgm_ctx->dibit_a_flag ) {
    remaining_cleartext = pgm_ctx->dibit_st_size = dfs.dibit_cnt;
  } else {
    int sts = mf_fstat(fd_in,&sb);
    if ( sts < 0 ) {
      printf("%s: Error fstat(fd,&sb) failed with errno = %d, strerror = <%s>\n",
	     __FUNCTION__,
	     errno,
	     strerror(errno));
      exit(0);
    }
    // Note: remaining_cleartext is just that for encoding, but
    // for decoding, it's the size of the remaining_ciphertext
    remaining_cleartext = pgm_ctx->dibit_st_size = sb.st_size;
  }
 
  //
  // create output file
  //

  // are we decrypting ???
  if ( pgm_ctx->dibit_d_flag ) {

    char template [ 32 ];

    // yes - create tmp file
    // get rid of old file if present

    if ( -1 == fd_out ) {
      sprintf(template,"zzTmpXXXXXX");
      fd_out = mf_mkstemp ( template );
      mkstemp_file = strdup ( template );
      if ( trace_flag > 1 ) printf("%s: created temp file <%s>\n",__FUNCTION__,mkstemp_file);
    }

  } else {
    // no - create cipher output file
    char namebuf [ 256 ];
    int trial = 0;
    struct stat trial_sb;
    int trial_sts;

    if ( -1 == file_out ) {
      // no - get next file from file system
      for ( trial = 0 ; trial < (BASE_DIBIT_FILE_MAX+1) ; trial++ ) {

	sprintf(namebuf,BASE_DIBIT_FILE_SPEC,trial);
	
	trial_sts = stat ( namebuf, &trial_sb );
	if ( trial_sts < 0 ) {
	  fd_out = mf_open ( namebuf, O_RDWR | O_CREAT | O_TRUNC , 0600 );
	  
	  if ( trace_flag ) printf("We are creating output file = <%s>\n",namebuf);
	  
	  break;
	}
      }
    }

    // make sure we were able to create a file
    if ( -1 == fd_out ) {
      printf("Error, can not create ciphertext file\n"
	     "Please delete some in this directory and try again.\n");
      exit(0);
    }
  }

  // make sure we are at the front of the file
  mf_lseek ( fd_in, 0, SEEK_SET );

  // do we decrypt ???
  if ( pgm_ctx->dibit_d_flag ) {
    // yes - decrypt
#include "decrypt.c"
  } else {
    // no - encrypt 
#include "encrypt.c"
  } // if d_flag

  // -a && ! -d
  if ( pgm_ctx->dibit_a_flag && !pgm_ctx->dibit_d_flag ) {
    // encoding, create a files record
    {
      unsigned int mrec     = mf_open ( "mfrec", 0, 0 );
      unsigned int mrec_out = mf_open ( "mfrec_out", 0, 0 );
      struct stat mrec_sb;
      AES_CFB aes_cfb;

      //
      // build mrec
      //

      if ( trace_flag > 1 )
	printf("%s:%d: writing k_flag = <%s>\n",
	       __FUNCTION__,__LINE__,k_flag);

      // out goes the key and a \0
      mf_write(mrec,k_flag,strlen(k_flag) + 1 );

      // out goes saved bits count
      mf_write(mrec,(char *)&pgm_ctx->key_file_saved_bits_cnt,sizeof(pgm_ctx->key_file_saved_bits_cnt));

      // next, the data
      mf_write(mrec,pgm_ctx->key_file_saved_bits,pgm_ctx->key_file_saved_bits_cnt);

#if 0
      {
	printf("%s:%d: saved pgm_ctx->key_file_saved_bits\n",__FUNCTION__,__LINE__);
	debug_show_block ( pgm_ctx->key_file_saved_bits, pgm_ctx->key_file_saved_bits_cnt);
      }
#endif

      // to front of file
      mf_lseek ( mrec, 0, SEEK_SET );
      mf_fstat ( mrec, &mrec_sb );

      //
      // encode mrec with aes_cfb
      //

      if ( trace_flag > 1 ) {
	printf("mrec size/16 = %d\n",(int)mrec_sb.st_size/16);
	printf("%s:%d: aes_cfb_init with mkey <%s>\n",
	       __FUNCTION__,__LINE__,m_key);
      }

      aes_cfb_init ( pgm_ctx,
		     &aes_cfb,
		     m_key );

      aes_cfb_encrypt ( pgm_ctx,
			&aes_cfb,
			mrec_sb.st_size / AES_BLOCK_SIZE,
			mf_get_data_ptr ( mrec ),
			mf_get_data_ptr ( mrec ));
      //
      // encode mrec with dibit
      //
      {
	int largc;
	char *largv[ 4 ];
	char lbuf [ 256 ];
	int x;
	char *c = lbuf;

	largc = 4;

	x = sprintf(c,"%s",argv[0]);
	largv [ 0 ] = c;
	c += x + 1;

	x = sprintf(c,"-n");
	largv [ 1 ] = c;
	c += x + 1;

	x = sprintf(c,"-k");
	largv [ 2 ] = c;
	c += x + 1;

	sprintf(c,"%s",m_key);
	largv [ 3 ] = c;

	dibit_main ( largc, largv, mrec, mrec_out );
      }

      // to front of file
      mf_lseek ( mrec_out, 0, SEEK_SET );
      // stat it
      mf_fstat ( mrec_out, &mrec_sb );

#if 0
      {
	printf("%s:%d: after dibit encryption, mrec_out size = %d bytes\n",
	       __FUNCTION__,__LINE__,
	       (int)mrec_sb.st_size);
	debug_show_block ( mf_get_data_ptr(mrec_out),mrec_sb.st_size);
      }
#endif

      //
      // marker -> fd_out
      //
      {
	unsigned char marker [ AES_BLOCK_SIZE ];

	memset(marker,0,AES_BLOCK_SIZE);

	mf_lseek(fd_out,0,SEEK_END);

	rw(mf_write,fd_out,marker,AES_BLOCK_SIZE);
      }

      //
      // mrec_out -> fd_out
      //

      mf_lseek(fd_out,0,SEEK_END);
      mf_lseek(mrec_out,0,SEEK_SET);
      mf_fstat(mrec_out,&mrec_sb);

      rw(mf_write,
	 fd_out,
	 mf_get_data_ptr ( mrec_out ),
	 mrec_sb.st_size);

      //
      // handle terminis 100000.... to
      // get (fd_out % AES_BLOCK_SIZE) = 0
      //

      mf_lseek(fd_out,0,SEEK_END);

      {
	struct stat sb;
	unsigned char d [ AES_BLOCK_SIZE ];
	int z;

	mf_fstat(fd_out,&sb);

	if ( !(z=(sb.st_size % AES_BLOCK_SIZE)) ) {
	  unsigned char last_byte;

	  // add 1, then 15 0's
	  // but only if last byte is 0x01

	  mf_lseek(fd_out,-1,SEEK_END);
	  rw(mf_read,fd_out,&last_byte,1);
	  if ( 0x01 == last_byte ) {
	    memset(d,0,AES_BLOCK_SIZE);
	    d[0] = 1;

	    rw(mf_write,
	       fd_out,
	       d,AES_BLOCK_SIZE);
	    
	    if ( trace_flag > 1 ) printf("%s: wrote full 10000.... block\n",__FUNCTION__);
	  } else {
	    if ( trace_flag > 1 ) printf("%s: no 10000.... pad needed\n",__FUNCTION__);
	  }

	} else {
	  // write some portion out
	  int cnt;

	  memset(d,0,AES_BLOCK_SIZE);
	  d[0] = 1;

	  cnt = AES_BLOCK_SIZE - z;

	  rw(mf_write,
	     fd_out,
	     d,cnt);

	  if ( trace_flag > 1 ) printf("%s: wrote %d  10000.... block\n",__FUNCTION__,cnt);
	}
      }

      mf_lseek(fd_out,0,SEEK_END);

      //
      // encrypt fd_out
      //
      {
	// so now that the entire output file is written,
	// and a multiple of AES_BLOCK_SIZE,
	// lets encrypt it with aes_cfb

	struct stat sb;
	unsigned char work_buf [ AES_BLOCK_SIZE ];
	off_t blk_cnt;
	off_t blk;

	mf_fstat(fd_out,&sb);

	blk_cnt = sb.st_size / AES_BLOCK_SIZE;
	blk     = 0;
       
	aes_cfb_init ( pgm_ctx,
		       &aes_cfb,
		       m_key );

	if ( trace_flag > 1 ) {
	  printf("%s: AES CFB encrypting fd_out, blk_cnt = %d\n",
		 __FUNCTION__,
		 (int)(sb.st_size / AES_BLOCK_SIZE));
	}

	mf_lseek(fd_out, 0, SEEK_SET );
	while ( blk_cnt > 0 ) {
	  rw(mf_read,fd_out,work_buf,AES_BLOCK_SIZE);

	  aes_cfb_encrypt ( pgm_ctx,
			    &aes_cfb,
			    1,
			    work_buf,
			    work_buf);

	  mf_lseek(fd_out, -AES_BLOCK_SIZE, SEEK_CUR );
	  rw(mf_write,fd_out,work_buf,AES_BLOCK_SIZE);

	  blk_cnt -= 1;
	  blk += 1;
	}

	if ( trace_flag > 1 ) printf("%s: AES_CFB encryption complete\n",__FUNCTION__);

#if 0
	{
	  printf("%s:%d: before encrypt\n",
		 __FUNCTION__,__LINE__);
	  debug_show_block ( m, AES_BLOCK_SIZE );
	}
	{
	  printf("%s:%d: after encrypt\n",
		 __FUNCTION__,__LINE__);
	  debug_show_block ( m, AES_BLOCK_SIZE );
	}
#endif
      }

      //
      // cleanup
      //
      mf_close( mrec );
      mf_close( mrec_out );
    }

    if ( pgm_ctx->dibit_z_flag ) {
      // get rid of used key bits in key_file.dat
      key_file_truncate ( pgm_ctx,
			  pgm_ctx->key_file_offset_start,                               /* hole start */
			  pgm_ctx->key_file_offset - pgm_ctx->key_file_offset_start + 1 /* hole size  */ );
    }

  } // if -a && ! -d

  // close output ???
  if ( file_out == -1 )
    mf_close(fd_out);
  if ( file_in == -1 )
    mf_close(fd_in);

#if 1
  // do we have to rename ???
  if ( pgm_ctx->dibit_d_flag && burried_output_file && mkstemp_file ) {
    int q;

    scrub ( burried_output_file, pgm_ctx->xsubi );
    unlink ( burried_output_file );
    rename ( mkstemp_file, burried_output_file );

    printf("%s: renamed <%s> as <%s>\n",
	   __FUNCTION__,
	   mkstemp_file,
	   burried_output_file);

    // get rid of burried_output_file, but zero it first
    q = strlen(burried_output_file);
    memset(burried_output_file,0,q);
    free ( burried_output_file );
  }
#endif

  // zero and delete cipher/clear text file ???
  if ( pgm_ctx->dibit_z_flag ) {
    // scrub
    scrub ( f_flag , pgm_ctx->xsubi );
    // unlink
    unlink ( f_flag );
    // and say so
    printf("Scrubbed and deleted file <%s>\n",f_flag);
  }

  if ( !pgm_ctx->dibit_d_flag && key_file_valid ( pgm_ctx ) ) {
    key_file_show_next_free ( pgm_ctx );
  }

  // close
  key_file_close ( pgm_ctx );

  // restore trace flag
  trace_flag = saved_trace_flag;

  //printf("%s: returning\n",__FUNCTION__);

  // done
  return 0;
}
