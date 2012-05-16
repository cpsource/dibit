#ifndef __dibit_h__
#define __dibit_h__

// track format of .dibit file
struct dibit_file_struct_t {
  off_t dibit_offset_start;
  off_t dibit_offset_last;
  int dibit_cnt;
  off_t mrec_key_start;
  off_t mrec_key_last;
  int mrec_key_cnt;
  off_t marker_offset_start;
};

// handle dibit
int dibit_main ( int argc, char *argv[], unsigned int file_in, unsigned int file_out );

#endif // __dibit_h__

