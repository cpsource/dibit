#ifndef __util_h__
#define __util_h__

#define min(a,b) ({	\
      int v = a; \
      if ( b < v ) v = b; \
      v; })

// set dibit
void set_dibit ( unsigned char *array, int bitno, int val );
// get dibit
int get_dibit ( unsigned char *array, int bitno );
// get bit
int get_bit ( unsigned char *array, int bitno );
// set bit
void set_bit ( unsigned char *array, int bitno, int val );
// clr bit
void clr_bit ( unsigned char *array, int bitno );

#endif // __util_h__
