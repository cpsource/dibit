#ifndef __config_h__
#define __config_h__

/* Copyright (C) 1998, compuPage, Inc. */

// the name of your key file
#define KEY_FILE_NAME "key_file.dat"

// base .dibit file spec
#define BASE_DIBIT_FILE_SPEC "zz.%05d.dibit"
#define BASE_DIBIT_FILE_MAX 99999

/* number of bits in ripemd160 */
/* this is the only size supported */
#define RMDsize 160

/* buid up to 192 bits in each lfsr */
#define MAX_LFSR_BITS 192

// define to use SHA1 algorithm instead of RMD160
// Copyright issues with RMD160 prevent it from being used
#define USE_SHA1

// handle linux stupid api
#define rw(cmd,fd,buf,cnt) ({			\
      unsigned int l_sts;			\
      unsigned int l_flag;			\
      do {					\
	l_sts = cmd ( fd, buf, cnt );		\
	if ( l_sts == -1 ) {			\
	  if ( errno == EINTR ) {		\
	    l_flag = 1;				\
	  } else {							\
	    printf("%s: Error, errno = %d <%s>, file = <%s>, line = %d\n", \
		   __FUNCTION__,					\
		   errno, strerror(errno),				\
		   __FILE__,__LINE__);					\
	    exit(0);							\
	  }								\
	} else {							\
	  l_flag = 0;							\
	}								\
      } while ( l_flag );						\
      l_sts; })

// zero then free a string
#define zfree(str) ({	     \
      int len = strlen(str); \
      memset(str,0,len);     \
      free(str);	     \
    })

// define this uniquely to help strengthen key if needed
#define KEY_ASSIST 0xdeadface

// define to try rbit test
// Note: This test was successful and it speeds up the algoritym by 4x
//       to about 4k bits per second on a reasonably fast cpu.
#define USE_RBIT_TEST

// define to mix the pseudo-random streams
#define USE_MIX_STREAMS

// macro to help keep array accesses in range
#define in_range(idx,table_size) ({				      \
      if ( idx < 0 || idx >= table_size ) {			      \
	printf("%s:%d: in_range failed, idx = %d, table_size = %d\n", \
	       __FILE__, __LINE__,idx,table_size);		      \
        exit(0);						      \
      }								      \
      idx;							      \
    })

// define as 1 to fuzz output
#define USE_FUZZ 1

// define to obscure last block
#define USE_LAST_BLOCK

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include "getkey.h"
#include "aes.h"
#include "gmpbbs.h"
#include "pgm_ctx.h"

#include "lfsr.h"
#include "scrub.h"
#include "cache.h"
#include "key_file.h"
#include "cell.h"
#include "aes_pseudo.h"
#include "bbs_pseudo.h"
#include "urandom_pseudo.h"
#include "mf.h"
#include "aes_cfb.h"
#include "key_mgmt.h"
#include "debug.h"
#include "last_block.h"

#endif /* __config_h__ */
