#ifndef __mf_h__
#define __mf_h__

// open a memory file
unsigned int mf_open ( char *name, int flags, int initial_size );
// close a memory file
unsigned int mf_close ( unsigned int mf_fd );
// fstat a memory file
unsigned int mf_fstat ( unsigned int mf_fd, struct stat *sb );
// write
unsigned int mf_write ( unsigned int mf_fd, char *buf, int cnt );
// lseek
unsigned int mf_lseek ( unsigned int mf_fd, off_t offset, int flag );
// read
unsigned int mf_read ( unsigned int mf_fd, char *buf, int cnt );
// get data ptr
unsigned char *mf_get_data_ptr ( unsigned int mf_fd );
// ftruncate
unsigned int mf_ftruncate ( unsigned int mf_fd, off_t offset );
// mkstemp
unsigned int mf_mkstemp ( char *template );
// assign
void mf_assign ( unsigned int tgt_fd, unsigned int src_fd );

#endif // __mf_h__
