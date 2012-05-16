
#include "config.h"

#include "pgm_ctx.h"

extern int trace_flag;

// fine cell x,y size (Note: must be prime)
#define CELL_MAX 31

// run the cell pseudo-random generator once
static int get_new_val ( PGM_CTX *pgm_ctx, TOP_CELL *me );

#include "prime_table.c"

#define ARG_INRANGE(arg,max) ({	 \
      unsigned int v = arg;	 \
      if ( v < 0 ) {		 \
	v *= -1;		 \
	v %= max;	         \
	v = max - v;		 \
      } else {	                 \
	v %= max;		 \
      }                          \
      v; })

// abs
int abs ( int x )
{
  if ( x < 0 ) return -x;
  return x;
}

// get pointer to cell, handle wrap case
static CELL *get_cell ( PGM_CTX *pgm_ctx, int x, int y )
{
  x = ARG_INRANGE(x,CELL_MAX);
  y = ARG_INRANGE(y,CELL_MAX);
  
  return &(pgm_ctx->cell_cells)[y*CELL_MAX + x];
}

// init module
void cell_init ( PGM_CTX *pgm_ctx, KEYBUF_3_ITERATOR *kb3_i )
{
  int x,y;
  CELL *cell;
  int bits_used = kb3_i->bits_used;

  if ( trace_flag > 1 ) printf("%s: entry\n",__FUNCTION__);

  pgm_ctx->cell_move_x_idx = 1;
  pgm_ctx->cell_move_y_idx = 1;

  // create cells
  pgm_ctx->cell_cells = calloc ( CELL_MAX * CELL_MAX, sizeof(CELL) );
  memset(pgm_ctx->cell_cells,0, CELL_MAX * CELL_MAX * sizeof(CELL) );

  // populate cells
  for ( x = 0 ; x < CELL_MAX ; x++ ) { 
    for ( y = 0 ; y < CELL_MAX ; y++ ) {   

      unsigned int k = getNKeyBits_3_iterator ( pgm_ctx, 32, kb3_i );

      if ( !pgm_ctx->dibit_n_flag ) {

	//printf("%s: %d,%d, k from getNKeyBits_3_iterator = 0x%08x\n",__FUNCTION__,x,y,k);

	// and try to grab bits from the key_file.dat
	k ^= key_file_multi_bit ( pgm_ctx, 32 );

	//printf("%s: %d,%d, k ^= key_file_multi_bit 0x%08x\n",__FUNCTION__,x,y,k);
	
      }

      cell = get_cell ( pgm_ctx, x, y );

      cell->polarity = k & 1;
      if ( !cell->polarity ) cell->polarity = -1;
      cell->x_pos    = (k & 0xfffe )     % 512;
      cell->y_pos    = (k & 0xffff0000 ) % 512;
    }
  }

  // run the cell engine a bit to randomize it
  {
    int i,j,v;
    TOP_CELL top_cell;
    int x_cnt = getNKeyBits_3_iterator ( pgm_ctx, 6, kb3_i );

    //printf("%s: x_cnt = %d\n",__FUNCTION__,x_cnt);

    memset(&top_cell,0,sizeof(TOP_CELL));

    for ( j = 0 ; j < 1024*4 + x_cnt; j++ ) {
      for ( v = i = 0 ; i < 32 ; i++ ) {
	if ( get_new_val(pgm_ctx, &top_cell) ) v |= 1<<i;
      } // for
    }

    // set hits to 0
    for ( i = 0 ; i < CELL_MAX ; i++ ) {
      for ( j = 0 ; j < CELL_MAX ; j++ ) {
	cell = get_cell ( pgm_ctx, i, j );
	cell->hits = 0;
      } // j
    } // i
    
  }

  if ( trace_flag > 1 ) printf("%s: bits_used = %d\n",
			       __FUNCTION__,
			       kb3_i->bits_used - bits_used);

  // done
}

#if 0

// cell and its neighbors

-1, +1| 0,+1 | +1,+1
-1, 0 | cell | +1,0
-1, -1| 0,-1 | +1,-1

#endif

// run the cell pseudo-random generator once
static int get_new_val ( PGM_CTX *pgm_ctx, TOP_CELL *me )
{
  unsigned int dx, dy;
  unsigned int pdx,pdy;
  int spdx = me->x, spdy = me->y;
  int res;
  CELL *cell;
  int orig_top_cell_x = me->x;
  int orig_top_cell_y = me->y;

  // upper left
  cell = get_cell( pgm_ctx, me->x-1,me->y+1 );
  dx = abs ( me->cell.x_pos - cell->x_pos );
  dy = abs ( me->cell.y_pos - cell->y_pos );
  pdx = prime_table [ in_range(dx,512) ];
  pdy = prime_table [ in_range(dy,512) ];
  spdx += pdx * cell->polarity;
  spdy += pdy * cell->polarity;

  // upper
  cell = get_cell( pgm_ctx, me->x,me->y+1 );
  dx = abs ( me->cell.x_pos - cell->x_pos );
  dy = abs ( me->cell.y_pos - cell->y_pos );
  pdx = prime_table [ in_range(dx,512) ];
  pdy = prime_table [ in_range(dy,512) ];
  spdx += pdx * cell->polarity;
  spdy += pdy * cell->polarity;

  // upper right
  cell = get_cell( pgm_ctx, me->x+1,me->y+1 );
  dx = abs ( me->cell.x_pos - cell->x_pos );
  dy = abs ( me->cell.y_pos - cell->y_pos );
  pdx = prime_table [ in_range(dx,512) ];
  pdy = prime_table [ in_range(dy,512) ];
  spdx += pdx * cell->polarity;
  spdy += pdy * cell->polarity;

  // left
  cell = get_cell( pgm_ctx, me->x-1,me->y );
  dx = abs ( me->cell.x_pos - cell->x_pos );
  dy = abs ( me->cell.y_pos - cell->y_pos );
  pdx = prime_table [ in_range(dx,512) ];
  pdy = prime_table [ in_range(dy,512) ];
  spdx += pdx * cell->polarity;
  spdy += pdy * cell->polarity;

  // right
  cell = get_cell( pgm_ctx, me->x+1,me->y );
  dx = abs ( me->cell.x_pos - cell->x_pos );
  dy = abs ( me->cell.y_pos - cell->y_pos );
  pdx = prime_table [ in_range(dx,512) ];
  pdy = prime_table [ in_range(dy,512) ];
  spdx += pdx * cell->polarity;
  spdy += pdy * cell->polarity;

  // lower left
  cell = get_cell( pgm_ctx, me->x-1,me->y-1 );
  dx = abs ( me->cell.x_pos - cell->x_pos );
  dy = abs ( me->cell.y_pos - cell->y_pos );
  pdx = prime_table [ in_range(dx,512) ];
  pdy = prime_table [ in_range(dy,512) ];
  spdx += pdx * cell->polarity;
  spdy += pdy * cell->polarity;

  // lower
  cell = get_cell( pgm_ctx, me->x,me->y-1 );
  dx = abs ( me->cell.x_pos - cell->x_pos );
  dy = abs ( me->cell.y_pos - cell->y_pos );
  pdx = prime_table [ in_range(dx,512) ];
  pdy = prime_table [ in_range(dy,512) ];
  spdx += pdx * cell->polarity;
  spdy += pdy * cell->polarity;

  // lower right
  cell = get_cell( pgm_ctx, me->x+1,me->y-1 );
  dx = abs ( me->cell.x_pos - cell->x_pos );
  dy = abs ( me->cell.y_pos - cell->y_pos );
  pdx = prime_table [ in_range(dx,512) ];
  pdy = prime_table [ in_range(dy,512) ];
  spdx += pdx * cell->polarity;
  spdy += pdy * cell->polarity;

  //
  // change our position
  //
  me->x += spdx;
  me->y += spdy;

  // keep top_cell in range
  me->x = ARG_INRANGE(me->x,CELL_MAX);
  me->y = ARG_INRANGE(me->y,CELL_MAX);

  //
  // get result
  //
  cell = get_cell( pgm_ctx, me->x,me->y );
  res = cell->polarity > 0 ? 1 : 0;

  //
  // track cell hit
  //
  cell->hits += 1;

  //
  // flip value of cell
  //
  cell->polarity *= -1;

  //
  // jitter cell
  //
  cell->x_pos = ARG_INRANGE(spdx,512);
  cell->y_pos = ARG_INRANGE(spdy,512);

  //
  // jitter top_cell
  //
  me->cell.x_pos = ARG_INRANGE( ARG_INRANGE(spdx,512)+me->cell.x_pos, 512);
  me->cell.y_pos = ARG_INRANGE( ARG_INRANGE(spdy,512)+me->cell.y_pos, 512);

  //
  // make sure top_cell moves
  //
  if ( me->x == orig_top_cell_x ) {
    me->x = ARG_INRANGE( me->x + pgm_ctx->cell_move_x_idx, CELL_MAX );
    pgm_ctx->cell_move_x_idx *= -1;
  }
  if ( me->y == orig_top_cell_y ) {
    me->y = ARG_INRANGE( me->y + pgm_ctx->cell_move_x_idx, CELL_MAX );
    pgm_ctx->cell_move_y_idx *= -1;
  }

  // return
  return res;
}

// allocate a top_cell, init it, then return
TOP_CELL *cell_new_top_cell ( void )
{
  TOP_CELL *top_cell = (TOP_CELL *)malloc(sizeof(TOP_CELL));

  assert(top_cell!=NULL);

  // start in center
  top_cell->x = CELL_MAX / 2;
  top_cell->y = CELL_MAX / 2;
  top_cell->cell.x_pos = 512/2;
  top_cell->cell.y_pos = 512/2;
  top_cell->cell.polarity = 1;
  top_cell->cell.hits = 0;

  return top_cell;
}

//int cell_trace = 0;

// get some bits
unsigned int cell_get_bits ( PGM_CTX *pgm_ctx, TOP_CELL *top_cell, int bit_count )
{
  unsigned int v = 0;
  int i;

  for ( v = i = 0 ; i < bit_count ; i++ ) {
    if ( get_new_val(pgm_ctx, top_cell) ) v |= 1<<i;
  } // for

#if 0
  if ( 1 || cell_trace )
  {
    static unsigned int zcnt = 0;

    printf("%s: returning 0x%08x, zcnt = %d\n",
	   __FUNCTION__,
	   v,
	   ++zcnt);
  }
#endif
    
  return v;
}

#if defined(CP_TEST)

int main()
{
  TOP_CELL top_cell;
  int i,j;
  unsigned int v;
  CELL *cell;

  cell_init();

  // start in center
  top_cell.x = CELL_MAX / 2;
  top_cell.y = CELL_MAX / 2;
  top_cell.cell.x_pos = 512/2;
  top_cell.cell.y_pos = 512/2;
  top_cell.cell.polarity = 1;
  top_cell.cell.hits = 0;

  for ( j = 0 ; j < 1024*4 ; j++ ) {
    for ( v = i = 0 ; i < 32 ; i++ ) {
      if ( get_new_val(&top_cell) ) v |= 1<<i;

      //printf("top_cell x, y = %d,%d\n",top_cell.x,top_cell.y);

    } // for

    printf("0x%08x\n",v);
  }

#if 1
  // show hits
  for ( i = 0 ; i < CELL_MAX ; i++ ) {
    for ( j = 0 ; j < CELL_MAX ; j++ ) {
      cell = get_cell ( i, j );

      printf("%02d : %02d - hits %d, dx = %d, dy = %d, polarity = %d\n",
	     i,j,cell->hits,
	     cell->x_pos,cell->y_pos,cell->polarity);

    } // j
  } // i
#endif

}

#endif // CP_TEST
