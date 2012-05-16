// stdin -> xor -> stdout
//           ^
//         /dev/urandom

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

// define if you want to skip 0's or 1's

#define SKIP_BADS

int main ( )
{
  unsigned char b1,b2;
  int sts;
  int ur = open ( "/dev/urandom", O_RDONLY );

  while ( 1 ) {

  sts = read ( 0, &b1, 1 );
  if ( -1 == sts && EINTR == errno ) continue;
  if ( 0 == sts || -1 == sts ) break;

  redo1:;
  sts = read ( ur, &b2, 1 );
  if ( -1 == sts && EINTR == errno ) goto redo1;

  b1 ^= b2;

#if defined(SKIP_BADS)
  if ( 0x0 == b1 || 0xff == b1 ) {
    // bad, skip
    continue;
  }
#endif

  redo2:;
  write(1,&b1,1);
  if ( -1 == sts && EINTR == errno ) goto redo2;

  }

  close(ur);
  return 0;
}
