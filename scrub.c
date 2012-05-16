// use Gutmann erase scheme, for what it's worth

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "scrub.h"

#if 0
1 	(Random) 	(Random) 			
2 	(Random) 	(Random) 			
3 	(Random) 	(Random) 			
4 	(Random) 	(Random) 			
5 	01010101 01010101 01010101 	55 55 55
6 	10101010 10101010 10101010 	AA AA AA
7 	10010010 01001001 00100100 	92 49 24
8 	01001001 00100100 10010010 	49 24 92
9 	00100100 10010010 01001001 	24 92 49
10 	00000000 00000000 00000000 	00 00 00
11 	00010001 00010001 00010001 	11 11 11
12 	00100010 00100010 00100010 	22 22 22
13 	00110011 00110011 00110011 	33 33 33
14 	01000100 01000100 01000100 	44 44 44
15 	01010101 01010101 01010101 	55 55 55
16 	01100110 01100110 01100110 	66 66 66
17 	01110111 01110111 01110111 	77 77 77
18 	10001000 10001000 10001000 	88 88 88
19 	10011001 10011001 10011001 	99 99 99
20 	10101010 10101010 10101010 	AA AA AA
21 	10111011 10111011 10111011 	BB BB BB
22 	11001100 11001100 11001100 	CC CC CC
23 	11011101 11011101 11011101 	DD DD DD
24 	11101110 11101110 11101110 	EE EE EE
25 	11111111 11111111 11111111 	FF FF FF
26 	10010010 01001001 00100100 	92 49 24
27 	01001001 00100100 10010010 	49 24 92
28 	00100100 10010010 01001001 	24 92 49
29 	01101101 10110110 11011011 	6D B6 DB
30 	10110110 11011011 01101101 	B6 DB 6D
31 	11011011 01101101 10110110 	DB 6D B6
32 	(Random) 	(Random) 			
33 	(Random) 	(Random) 			
34 	(Random) 	(Random) 			
35 	(Random) 	(Random)
#endif // 0

typedef struct pattern_struct_t {
  int flag; // 0, use pattern, 1 use random
  unsigned int pat;
} PAT;

static PAT pats[35] = {
  { 1, 0 },
  { 1, 0 },
  { 1, 0 },
  { 1, 0 },

  { 0, 0x555555 },
  { 0, 0xAAAAAA },
  { 0, 0x924924 },
  { 0, 0x492492 },
  { 0, 0x249249 },
  { 0, 0x000000 },
  { 0, 0x111111 },
  { 0, 0x222222 },
  { 0, 0x333333 },
  { 0, 0x444444 },
  { 0, 0x555555 },
  { 0, 0x666666 },
  { 0, 0x777777 },
  { 0, 0x888888 },
  { 0, 0x999999 },
  { 0, 0xAAAAAA },
  { 0, 0xBBBBBB },
  { 0, 0xCCCCCC },
  { 0, 0xDDDDDD },
  { 0, 0xEEEEEE },
  { 0, 0xFFFFFF },
  { 0, 0x924924 },
  { 0, 0x492492 },
  { 0, 0x249249 },
  { 0, 0x6DB6DB },
  { 0, 0xB6DB6D },
  { 0, 0xDB6DB6 },

  { 1, 0 },
  { 1, 0 },
  { 1, 0 },
  { 1, 0 }
};

static char *f = NULL;

static void zorch_file ( char *fname , int flag, unsigned int pat, unsigned short *xsubi )
{
  struct stat sb;
  char *c;
  int cnt;
  unsigned int *x;
  int remain;
  int fd;

  fd = open ( fname, O_RDWR );
  if ( fd < 0 ) {
    return;
  }
  fstat(fd,&sb);

  if ( !f ) {
    f = (unsigned char *) malloc ( sb.st_size );
  }
  cnt = sb.st_size;
  c = f;
  x = (unsigned int *)c;

  if ( flag ) {
    // rand most of file
    cnt /= 4;
    while ( cnt-- > 0 ) {
      *x = nrand48(xsubi);
      x += 1;
    }
    // take care of remainder
    c = (unsigned char *)x;
    remain = sb.st_size - (sb.st_size/4)*4;
    while ( remain-- > 0 ) {
      *c = nrand48(xsubi);
      c += 1;
    }
  } else {
    // write data pattern
    cnt /= 4;
    while ( cnt-- > 0 ) {
      *x = pat;
      x += 1;
    }
    // take care of remainder
    c = (unsigned char *)x;
    remain = sb.st_size - (sb.st_size/4)*4;
    while ( remain-- > 0 ) {
      *c = pat;
      c += 1;
      pat >>= 8;
    }
  }

  // write file
  rw(write, fd,f,sb.st_size);
  close(fd);
}

// scrub
void scrub ( char *fname , unsigned short *xsubi )
{
  int i;

  for ( i = 0 ; i < 35 ; i++ ) {
    zorch_file ( fname ,
		 pats[i].flag,
		 pats[i].pat,
		 xsubi );
  }

  free(f);
  f = NULL;
}
