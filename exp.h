#ifndef __exp_h__
#define __exp_h__

int getSrBits ( int num, BS_PTR b, BS_PTR c, char *poly, char *poly1 );
void initSr( BS_PTR b, BS_PTR c, char *poly, char *poly1, KEYBUF_PTR kb);

void getkey ( char *s , KEYBUF_PTR kp );
int nextKeyBit ( KEYBUF_PTR kp );
aDat getNKeyBits ( int n, KEYBUF_PTR kp );
int unUsedBits ( KEYBUF_PTR kp );

/* get 'nnn' random bits from the proton array */
unsigned int gint( int nnn );

/* show the dot */
//void show_dot ( DOT_PTR d );

void adj_dot();

/* save off a transformation matrix */
void copy_xform ( int *src, int *tgt );

#endif /* __exp_h__ */

