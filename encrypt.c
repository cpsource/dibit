// encrypt

    // work entire file
    while ( remaining_cleartext ) {
      int cleartext_cnt;
      int salt_cnt;
      // number of bytes in this work group
      int workgroup_size;
      int fuzz_offset;
      char *c;
      //static int first_salt_flag = 0; // if 0, add cleartext file name to front of salt
      int sts;

      // get number of bytes of cleartext to process in this workgroup
      cleartext_cnt        = (GET_PSEUDO_CONTROLLER_BITS(24) % 1024 + 512) + 1024;
      cleartext_cnt        = min(remaining_cleartext,cleartext_cnt);
      salt_cnt             = (GET_PSEUDO_CONTROLLER_BITS(13) % 1024) + 512;
      fuzz_offset          = (GET_PSEUDO_CONTROLLER_BITS(3) % 6) + 1;

      workgroup_size       = cleartext_cnt + salt_cnt;
      remaining_cleartext -= cleartext_cnt;

      if ( trace_flag > 1 ) printf("allocating work buffers\n");

      printf("cleartext_cnt = %4d, salt_cnt = %4d, workgroup_size = %4d, remaining_cleartext = %5d, fuzz = %d\n",
	     cleartext_cnt,
	     salt_cnt,
	     workgroup_size,
	     remaining_cleartext,
	     fuzz_offset);

#if defined(CACHE_TEST)
      // init dibit cache
      cache_init_ces ( pgm_ctx->ctx, workgroup_size * 8 );
#if defined(USE_RBIT_TEST)
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
      // dibuf_tst = malloc ( workgroup_size*2 );
      // memset(dibuf_tst,0,workgroup_size*2);
#endif

      if ( trace_flag > 1 ) printf("reading cleartext\n");

      // get data
      sts = rw(mf_read, fd_in,ibuf,cleartext_cnt);
      if ( sts != cleartext_cnt ) {
	printf("read reports error, sts = %d, cleartext_cnt = %d\n",sts,cleartext_cnt);
	exit(0);
      }

      // fill in salt
      c = &ibuf [ cleartext_cnt ];

      if ( !pgm_ctx->dibit_first_salt_flag ) {
	// add cleartext file name to front of salt
	pgm_ctx->dibit_first_salt_flag = sprintf(c,"%s",f_flag);

#if 0
	printf("%s: wrote file name <%s>\n",
	       __FUNCTION__,
	       f_flag);
#endif

	c [ pgm_ctx->dibit_first_salt_flag ] = 0; // terminate string with \0
	// adjust ptr, salt_cnt
	c        += (pgm_ctx->dibit_first_salt_flag + 1);
	salt_cnt -= (pgm_ctx->dibit_first_salt_flag + 1);
	// check salt_cnt just in case
	if ( salt_cnt < 0 ) {
	  printf("Error, salt_cnt has gone minus, please adjust dibit constants and retry\n");
	  exit(0);
	}
      }

      // try to salt in index.html
      if ( !get_index_html( c, salt_cnt, pgm_ctx->xsubi ) ) {
	// we were not successful, just usr Xrand48 data instead
	for ( i = 0 ; i < salt_cnt ; i++ ) {
	  *c ^= nrand48(pgm_ctx->xsubi);
	  c += 1;
	}
      }

      if ( trace_flag > 1 ) printf("building dibit array\n");

      // build dibit array
      bitcount = workgroup_size * 8;
      for ( i = 0 ; i < bitcount ; i++ ) {
	set_dibit ( dibuf, i,
		    get_bit ( ibuf, i ));
      }

#if defined(CACHE_TEST)
      //memcpy(dibuf_tst,dibuf,workgroup_size*2);
#endif

      if ( trace_flag > 1 ) printf("building output\n");

      // build output
      randmod = bitcount;
      for ( i = 0 ; i < bitcount ; i++, randmod -= 1 ) {
#if defined(CACHE_TEST)
	//int m,n;
#endif
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

#if defined(CACHE_TEST)
#if 1
#if defined(USE_RBIT_TEST)

#if 0
	if ( !pgm_ctx->dibit_n_flag )
	{
	  static int zcnt = 64;

	  if ( zcnt-- > 0 ) {
	    printf("encrypt: rbit_rnd = %d, rnd = %d, dat_rnd = %d, randmod = %d\n",
		   rbit_rnd,
		   rnd,
		   dat_rnd,
		   randmod);
	  }
	}
#endif

	set_dibit ( obuf,
		  cache_find_rbit ( pgm_ctx->rbit_ctx, obuf, rbit_rnd),
		  cache_find_dibit( pgm_ctx->ctx, dibuf, rnd) ^ dat_rnd );
#else
	set_bit ( obuf,
		  get_rbit (rbuf, rbit_rnd),
		  cache_find_dibit( pgm_ctx->ctx, dibuf, rnd) ^ dat_rnd );
#endif
#else
	set_bit ( obuf,
		  get_rbit (rbuf, rbit_rnd),
		  (m=get_dibit ( dibuf, rnd )) ^ dat_rnd );

	n = cache_find_dibit ( ctx, dibuf_tst, rnd, workgroup_size * 8 );
	if ( m != n ) {
	  printf("%s: get_dibit returns %d, cache_find_dibit returns %d, rnd = %d\n",
		 __FUNCTION__,
		 m,n,rnd);
	  exit(0);
	}
#endif // 1
#else
	set_bit ( obuf,
		  get_rbit (rbuf, rbit_rnd),
		  get_dibit ( dibuf, rnd ) ^ dat_rnd );
#endif
      }

#if defined(USE_RBIT_TEST)

      // create output file starting at a certain bit position 'off'
      if ( USE_FUZZ )
      {
	int i;
	unsigned char dat;
	int workgroup_size_bitcnt = workgroup_size * 8;
	int off = fuzz_offset; // bit offset to start writing

	for ( dat = 0, i = 0 ; i < workgroup_size_bitcnt ; i++ ) {
	  if ( get_dibit ( obuf, i ) ) dat |= (1<<off);
	  off += 1;
	  if ( off > 7 ) {
	    off = 0;
	    // write output
	    rw(mf_write, fd_out,&dat,1);
	    dat = 0;
	  }
	}
	if ( off )
	  rw(mf_write, fd_out,&dat,1);
      } else {
	int i;
	unsigned char dat;

	for ( i = 0 ; i < workgroup_size ; i++ ) {
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
#else
      // write output
      rw(mf_write, fd_out,obuf,workgroup_size);
#endif
      
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

#if defined(CACHE_TEST)
      //memset(dibuf_tst,0,workgroup_size*2);
      //free(dibuf_tst);
#endif

    } // while ( remaining_cleartext )
