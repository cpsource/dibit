#ifndef __sha1_h__
#define __sha1_h__

// compute sha1
//
// digest -> 20 bytes output
// in     -> 64 bytes input
// W      -> 320 bytes scratch
//
void sha_transform(unsigned int *digest, const char *in, unsigned int *W);

// init
//
// buf    -> 20 bytes output
//
void sha_init(unsigned int *buf);

#endif // __sha1_h__
