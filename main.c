
// a wrapper for dibit

#include "config.h"

#include "dibit.h"

int trace_flag = 1;

int main ( int argc, char *argv[] )
{
  int sts;

  sts = dibit_main ( argc, argv, -1, -1 );

  return sts;
}
