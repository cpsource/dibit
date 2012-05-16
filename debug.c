
#include "config.h"

void debug_show_block ( char *array, int cnt )
{
  int i,j,k = 0;

  printf("cnt = %d\n",cnt);

  printf("\n%04d: ",k); k += 16;
  for ( j = i = 0 ; i < cnt ; i++ ) {
    printf("0x%02x ",
	   array[i] & 0xff);
    if ( ++j > 15 ) {
      j = 0;
      printf("\n%04d: ",k); k += 16;
    }
  }
  if ( j ) printf("\n");
}
