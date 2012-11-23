#ifndef __wabit_h__
#define __wabit_h__

// gen, calculate sha1, append, encrypt
void wabbit_gen ( unsigned char *key, unsigned int fd );
// chk, decrypt, return TRUE if sha1 ok, else FALSE
int wabbit_chk ( unsigned char *key, unsigned int fd_in, unsigned int fd_out );

#endif // __wabit_h__
 
