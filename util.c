#include "util.h"

//
// get_bit - return a single bit from the given array
//   array: pointer to the bit array
//   bitno: bit offset to retrieve
//   returns: 0 or 1 depending on the value of the bit
//
int get_bit ( unsigned char *array, int bitno )
{
  int off = bitno / 8;
  int bit = bitno % 8;
  int mask = 1<<bit;

  return array[off] & mask ? 1 : 0;
}

//
// clr_bit - clear a single bit in the array
//   array: pointer to the bit array
//   bitno: bit offset to clear
//
void clr_bit ( unsigned char *array, int bitno )
{
  int off = bitno / 8;
  int bit = bitno % 8;
  int mask = 1<<bit;

  array[off] &= ~mask;
}

//
// set_bit - set or clear a bit in the array
//   array: pointer to the bit array
//   bitno: bit offset to modify
//   val  : value to write (0 or 1)
//
void set_bit ( unsigned char *array, int bitno, int val )
{
  int off = bitno / 8;
  int bit = bitno % 8;
  int mask = 1<<bit;

  if ( val ) array[off] |= mask;
}

//
// set_dibit - store a two bit value into the array
//   array: pointer to the dibit array
//   bitno: dibit offset to modify
//   val  : value to store (0 or 1)
//
void set_dibit ( unsigned char *array, int bitno, int val )
{
  int off = bitno / 4;
  int bit = bitno % 4;
  int mask = 1<<(bit*2);

  if ( val ) array[off] |= mask;
}

//
// get_dibit - fetch a two bit value from the array
//   array: pointer to the dibit array
//   bitno: dibit offset to read
//   returns: 0 or 1
//
int get_dibit ( unsigned char *array, int bitno )
{
  int off = bitno / 4;
  int bit = bitno % 4;
  int mask = 1<<(bit*2);

  return array[off] & mask ? 1 : 0;
}


//
// get_index_html - copy random data from index.html into buf
//   buf   : output buffer
//   cnt   : number of bytes to copy
//   xsubi : seed for nrand48 used to randomize file offsets
//   returns 1 on success, 0 on failure
//
int get_index_html ( char *buf, int cnt, unsigned short *xsubi )
{
  static int fd = -1;
  int sts;
  static int msg_flag = 1;
  static int first_random_place = 1;
  int random_place;

  if ( -1 == fd ) {
    char *dibit_base;
    fd = open ( "index.html", O_RDONLY );
    if ( fd < 0 && (dibit_base = getenv("DIBIT_BASE")) != NULL ) {
      char index_html_name [ 256 ];
      sprintf( index_html_name, "%s/%s", dibit_base, "index.html" );
      fd = open ( index_html_name , O_RDONLY );
    }
  }

  if ( fd < 0 ) {
    if ( msg_flag ) {
      printf("To increase randomness of the nrand48 function,\n"
         "(used to generate salt), create index.html in this directory.\n");
      printf("Example: sh index.sh\n");
      msg_flag = 0;
    }
    memset(buf,0,cnt);
    return 0;
  }

  // go to some random place
  if ( first_random_place ) {
    struct stat sb;
    fstat(fd,&sb);
    first_random_place = 0;
    random_place = nrand48(xsubi) % sb.st_size;
    rw(lseek,fd,random_place,SEEK_SET);
  }

  sts = rw(read, fd, buf, cnt );
  if ( sts < cnt ) {
    // we could not get it all
    // just reset to the front of the file and read again

    if ( trace_flag ) printf("%s: resetting to front of file\n",__FUNCTION__);

    rw(lseek,fd,0,SEEK_SET);

    rw(read, fd, &buf[sts] , cnt - sts );
  }
  return 1;
}
