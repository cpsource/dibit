#ifndef __cell_h__
#define __cell_h__

#include "getkey.h"

#if 0

// cell and its neighbors

-1, +1| 0,+1 | +1,+1
-1, 0 | cell | +1,0
-1, -1| 0,-1 | +1,-1

#endif

// define what's in a cell
typedef struct cell_struct_t {

  int polarity;      // 1 for +, -1 for negative
  int x_pos, y_pos;  // x and y pos of item in cell [0..511] starting at lower right
  unsigned int hits; // number of hits

} CELL;

// define what's in a top_cell
typedef struct top_cell_struct_t {

  int x,y;           // position in cells array
  CELL cell;         // and just standard cell data

} TOP_CELL;

// init
void cell_init ( PGM_CTX *pgm_ctx, KEYBUF_3_ITERATOR *kb3_i );
// allocate a top_cell, init it, then return
TOP_CELL *cell_new_top_cell ( void );

struct pgm_ctx_struct_t;

// get some bits
unsigned int cell_get_bits ( struct pgm_ctx_struct_t *pgm_ctx, TOP_CELL *top_cell, int bit_count );

#endif // __cell_h__
