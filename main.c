
// a wrapper for dibit

#include "config.h"

#include "dibit.h"

int trace_flag = 1;

int main ( int argc, char *argv[] )
{
  int sts;

#if defined(USE_DIFFUSER_TEST)
#include "diffuser.h"
  // test the diffuser
  diffuser_test ( "MickeyMouse" );
  exit(0);
#endif

  sts = dibit_main ( argc, argv, -1, -1 );

  return sts;
}
