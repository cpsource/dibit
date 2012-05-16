// decrypt

#define remaining_ciphertext remaining_cleartext

    // work entire file
    while ( remaining_ciphertext ) {
      int cleartext_cnt;
      int salt_cnt;
      // number of bytes in this work group
      int workgroup_size;
      int fuzz_offset;
      //char *c;
      //static int first_salt_flag = 0; // if 0, add cleartext file name to front of salt
      int sts;

      // get number of bytes of cleartext to process in this workgroup
      cleartext_cnt        = (GET_PSEUDO_CONTROLLER_BITS(24) % 1024 + 512) + 1024;
      salt_cnt             = (GET_PSEUDO_CONTROLLER_BITS(13) % 1024) + 512;
      fuzz_offset          = (GET_PSEUDO_CONTROLLER_BITS(3)  % 6) + 1;
      workgroup_size       = cleartext_cnt + salt_cnt;
      if ( workgroup_size > remaining_ciphertext ) {
	// at EOF
	cleartext_cnt        = remaining_ciphertext - (salt_cnt + USE_FUZZ);
	workgroup_size       = remaining_ciphertext - USE_FUZZ;
	remaining_ciphertext = 0;
      } else {
	remaining_ciphertext -= (workgroup_size + USE_FUZZ);
      }

      if ( trace_flag > 1 ) printf("allocating work buffers\n");

      printf("cleartext_cnt = %4d, salt_cnt = %4d, workgroup_size = %4d, remaining_ciphertext = %5d, fuzz = %d\n",
	     cleartext_cnt,
	     salt_cnt,
	     workgroup_size,
	     remaining_ciphertext,
	     fuzz_offset);

#if defined(CACHE_TEST)
      // init dibit cache
      cache_init_ces ( pgm_ctx->ctx, workgroup_size * 8 );
#if defined(USE_RBIT_TEST)
      // init rbuf dibit cache
      cache_init_ces ( pgm_ctx->rbit_ctx, workgroup_size * 8 );
#endif // USE_RBIT_TEST
#endif // CACHE_TEST

      // allocate some temp buffers
      ibuf = malloc ( workgroup_size );
      memset(ibuf,0,workgroup_size);

#if defined(USE_RBIT_TEST)
      obuf = malloc ( workgroup_size * 2 );
      memset(obuf,0,workgroup_size * 2 );
#else
      obuf = malloc ( workgroup_size );
      memset(obuf,0,workgroup_size );
      rbuf = malloc ( workgroup_size );
      memset(rbuf,0,workgroup_size);
#endif

      dibuf = malloc ( workgroup_size*2 );
      memset(dibuf,0,workgroup_size*2);

#if defined(CACHE_TEST)
      //dibuf_tst = malloc ( workgroup_size*2 );
      //memset(dibuf_tst,0,workgroup_size*2);
#endif
      
      if ( trace_flag > 1 ) printf("reading cleartext\n");

      if ( USE_FUZZ )
      {
	int i;
	unsigned char dat;
	int workgroup_size_bitcnt = workgroup_size * 8;
	int off = fuzz_offset; // bit offset to start reading

	rw(mf_read, fd_in, &dat, 1);
	for ( i = 0 ; i < workgroup_size_bitcnt ; i++ ) {

	  set_bit ( ibuf, i,
		    dat & (1<<off) ? 1 : 0 );

	  off += 1;
	  if ( off > 7 ) {
	    off = 0;
	    // read input
	    rw(mf_read, fd_in, &dat, 1);
	  }
	}
      } else {
	// get data - ciphertext + salt
	sts = rw(mf_read, fd_in,ibuf,workgroup_size);
	if ( sts != workgroup_size ) {
	  printf("read reports error, sts = %d, workgroup_size = %d\n",sts,workgroup_size);
	  exit(0);
	}
      }

      if ( trace_flag > 1 ) printf("building dibit array\n");

      // build dibit array
      bitcount = workgroup_size * 8;
      for ( i = 0 ; i < bitcount ; i++ ) {
	set_dibit ( dibuf, i,
		    get_bit ( ibuf, i ));
      }

      if ( trace_flag > 1 ) printf("building output\n");

      // build output
      randmod = bitcount;
      for ( i = 0 ; i < bitcount ; i++, randmod -= 1 ) {
	unsigned int mix_2 = 0;
	unsigned int mix_3 = 0;

	// first pseudo-random seq - which input bit to select    
	rnd = cell_get_bits(pgm_ctx,pgm_ctx->top_cell,32) % randmod; 

#if defined(USE_MIX_STREAMS)
	if ( cell_get_bits(pgm_ctx,pgm_ctx->top_cell,1) ) {
	  mix_3 = -1;
	} else {
	  mix_3 = 0;
	}
#endif
#if defined(USE_BBS)
	if ( ! pgm_ctx->dibit_n_flag )
	{
	  union {
	    unsigned char r[4];
	    unsigned int x;
	  } v;

	  // get multi-bits from BBS_PSEUDO
	  v.r[0] = bbs_pseudo_get_multi_bit ( pgm_ctx, 8 );
	  v.r[1] = bbs_pseudo_get_multi_bit ( pgm_ctx, 8 );
	  v.r[2] = bbs_pseudo_get_multi_bit ( pgm_ctx, 8 );
	  v.r[3] = bbs_pseudo_get_multi_bit ( pgm_ctx, 8 );

	  mix_2 = v.x;
	}
#endif

	// second pseudo-random seq - where to place this bit in output
	rbit_rnd = (get_dual_lfsr_bits ( 32, &pgm_ctx->second_pseudo_random_sequence ) ^ mix_2) % randmod; 
	// third pseudo-random seq - xor with input data
	dat_rnd = ((get_dual_lfsr_bits ( 32, &pgm_ctx->third_pseudo_random_sequence ) ^ mix_3) % randmod) & 1;            

	// eye candy
	if ( trace_flag > 1 ) {
	  if ( !(randmod & 0xfff) ) {
	    printf("... bits remaining %d\n",randmod);
	  }
	}

#if 1
#if defined(USE_RBIT_TEST)

#if 0
	if ( !pgm_ctx->dibit_n_flag )
	{
	  static int zcnt = 64;

	  if ( zcnt-- > 0 ) {
	    printf("decrypt: rbit_rnd = %d, rnd = %d, dat_rnd = %d, randmod = %d\n",
		   rbit_rnd,
		   rnd,
		   dat_rnd,
		   randmod);
	  }
	}
#endif

	set_dibit ( obuf,
		    cache_find_rbit (pgm_ctx->rbit_ctx,obuf,rnd),
		    cache_find_dibit ( pgm_ctx->ctx, dibuf, rbit_rnd ) ^ dat_rnd );
#else // USE_RBIT_TEST
	set_bit ( obuf,
		  get_rbit (rbuf, rnd),
		  cache_find_dibit ( pgm_ctx->ctx, dibuf, rbit_rnd ) ^ dat_rnd );
#endif // USE_RBIT_TEST
#else
	set_bit ( obuf,
		  get_rbit (rbuf, rnd),
		  get_dibit ( dibuf, rbit_rnd ) ^ dat_rnd );
#endif
      }

#if defined(USE_RBIT_TEST)
      {
	int i;
	unsigned char dat;

	for ( i = 0 ; i < cleartext_cnt ; i++ ) {
	  dat = 0;

	  if ( get_dibit ( obuf, i*8 + 0 ) ) dat |= (1<<0);
	  if ( get_dibit ( obuf, i*8 + 1 ) ) dat |= (1<<1);
	  if ( get_dibit ( obuf, i*8 + 2 ) ) dat |= (1<<2);
	  if ( get_dibit ( obuf, i*8 + 3 ) ) dat |= (1<<3);

	  if ( get_dibit ( obuf, i*8 + 4 ) ) dat |= (1<<4);
	  if ( get_dibit ( obuf, i*8 + 5 ) ) dat |= (1<<5);
	  if ( get_dibit ( obuf, i*8 + 6 ) ) dat |= (1<<6);
	  if ( get_dibit ( obuf, i*8 + 7 ) ) dat |= (1<<7);

	  // write output
	  rw(mf_write, fd_out,&dat,1);
	}
      }

      // file name
      if ( !pgm_ctx->dibit_first_salt_flag ) {

	char output_file [ 256 ];
	char *o_c = output_file;
	int o_cnt = sizeof(output_file) - 1;
	int o_i;
	unsigned char dat;

	// must dig the file name out of the salt
	o_i = cleartext_cnt;
	while ( 1 ) {
	  dat = 0;

	  if ( get_dibit ( obuf, o_i*8 + 0 ) ) dat |= (1<<0);
	  if ( get_dibit ( obuf, o_i*8 + 1 ) ) dat |= (1<<1);
	  if ( get_dibit ( obuf, o_i*8 + 2 ) ) dat |= (1<<2);
	  if ( get_dibit ( obuf, o_i*8 + 3 ) ) dat |= (1<<3);

	  if ( get_dibit ( obuf, o_i*8 + 4 ) ) dat |= (1<<4);
	  if ( get_dibit ( obuf, o_i*8 + 5 ) ) dat |= (1<<5);
	  if ( get_dibit ( obuf, o_i*8 + 6 ) ) dat |= (1<<6);
	  if ( get_dibit ( obuf, o_i*8 + 7 ) ) dat |= (1<<7);

	  // save off
	  *o_c = dat;
	  o_c += 1;
	  o_i += 1;
	  o_cnt -= 1;

	  // done ???
	  if ( !o_cnt || !dat ) break;
	} // while 1
	*o_c = 0;

#if 0
	// TODO - come up with a better name to recognize valid file names
	if ( strlen(output_file) > 5 ) {
	  printf("%s: output file name too big\n",__FUNCTION__);
	  exit(0);
	}
#endif

	if ( !pgm_ctx->dibit_n_flag ) {
	  burried_output_file = strdup ( output_file );
	  if ( 1 || trace_flag > 1 ) printf("Creating Output File: %s\n",burried_output_file);
	  //printf("decrypt.c:%d: exiting\n",__LINE__);
	  //exit(0);
	}

	pgm_ctx->dibit_first_salt_flag = 1;
	//exit(0);
	//fd_out = open ( burried_output_file, O_TRUNC | O_CREAT | O_RDWR, 0600 );
      }

#else // USE_RBIT_TEST

      // write output
      rw(mf_write, fd_out,obuf,cleartext_cnt);

      // save off file name
      if ( !pgm_ctx->dibit_first_salt_flag ) {
	burried_output_file = strdup ( &obuf[cleartext_cnt] );
	pgm_ctx->dibit_first_salt_flag = 1;
      }

#endif // USE_RBIT_TEST

      // cleanup for next round
      memset(ibuf,0,workgroup_size);
      free(ibuf);
      memset(obuf,0,workgroup_size);
      free(obuf);
#if !defined(USE_RBIT_TEST)
      memset(rbuf,0,workgroup_size);
      free(rbuf);
#endif
      memset(dibuf,0,workgroup_size*2);
      free(dibuf);

    } // while ( remaining_ciphertext )
