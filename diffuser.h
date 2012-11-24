#ifndef __diffuser_h__
#define __diffuser_h__

// diffuse
void diffuse_diffuse ( char *key, unsigned int fd, off_t small_entropy_start );

// un_diffuse
void diffuse_un_diffuse ( char *key, unsigned int fd, off_t small_entropy_start );

#if defined(USE_DIFFUSER_TEST)
// test diffuser
void diffuser_test ( char *key );
#endif

#endif // __diffuser_h__
