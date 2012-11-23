// mf - memory file - mimics open/close/read/writre execpt in memory

#include <sys/mman.h>

#include "config.h"

// initial size for memory file
#define MF_INITIAL_SIZE (8192*2)

// our structure type
typedef struct mf_struct_t {

  off_t mf_offset;          // current offset
  off_t st_size;            // number of bytes in file

  unsigned int mf_data_max; // current max of mf_data
  unsigned char *mf_data;   // points to data

  // linux things
  unsigned char *mf_addr;   // if mmapped
  size_t mf_len;            // if mmapped
  int mf_real_fd;           // if its a real file, the fd is here
} MF;

#define min(a,b) ({	\
      int v = a; \
      if ( b < v ) v = b; \
      v; })

#define max(a,b) ({	\
      int v = a; \
      if ( b > v ) v = b; \
      v; })

extern int trace_flag;

// assign
void mf_assign ( unsigned int tgt_fd, unsigned int src_fd )
{
  MF *mf_tgt = (MF *)tgt_fd;
  MF *mf_src = (MF *)src_fd;

  close(mf_tgt->mf_real_fd);

  memcpy(mf_tgt,mf_src,sizeof(MF));

  memset(mf_src,0,sizeof(MF));
  free(mf_src);
}

// mkstemp
unsigned int mf_mkstemp ( char *template )
{
  MF *mf = (MF *)malloc(sizeof(MF));
  assert(mf!=NULL);
  memset(mf,0,sizeof(MF));

  if ( 0 == strcmp(template,"memory") ) {
    int initial_size = MF_INITIAL_SIZE;
    mf->mf_data = (unsigned char *)malloc(initial_size);
    assert(mf->mf_data!=NULL);
    memset(mf->mf_data,0,initial_size);
    mf->mf_data_max = initial_size;

    mf->mf_real_fd = -1;
  } else {
    mf->mf_real_fd = mkstemp ( template );
  }

  // done
  return (unsigned int)mf;
}

// ftruncate
unsigned int mf_ftruncate ( unsigned int mf_fd, off_t offset )
{
  MF *mf = (MF *)mf_fd;

  if ( -1 != mf->mf_real_fd ) {
    unsigned int sts;
    sts = ftruncate ( mf->mf_real_fd, offset );
    return sts;
  }

  if ( offset > mf->st_size ) {
    // can't do this
    return -1;
  }

  // zero out stuff we no longer want to access
  memset( &mf->mf_data [ offset ], 0, mf->st_size - offset );

  // set the new size to what user requested
  mf->st_size = offset;

  // done
  return 0;
}

// get data ptr
unsigned char *mf_get_data_ptr ( unsigned int mf_fd )
{
  MF *mf = (MF *)mf_fd;
  struct stat sb;

  // linux file descriptor ???
  if ( -1 != mf->mf_real_fd ) {
    // yes, use it to mmap file
    fstat(mf->mf_real_fd,&sb);
    // remap ???
    if ( sb.st_size != mf->mf_len ) {
      // yes, close out old one
      munmap ( mf->mf_addr, mf->mf_len );
    } else {
      // no, just return ptr
      if ( mf->mf_addr ) {
	return mf->mf_addr;
      }
    }
    mf->mf_len = (size_t)sb.st_size;
    mf->mf_addr = mmap ( NULL,
		      mf->mf_len,
		      PROT_READ | PROT_WRITE,
		      MAP_PRIVATE,
		      mf->mf_real_fd,
		      0 );
    return &mf->mf_addr [ mf->mf_offset ];
  }

  return &mf->mf_data [ mf->mf_offset ];
}

// read
unsigned int mf_read ( unsigned int mf_fd, char *buf, int cnt )
{
  MF *mf = (MF *)mf_fd;
  int mcnt = min ( cnt, mf->st_size - mf->mf_offset );

  if ( -1 != mf->mf_real_fd ) {
    unsigned int sts;
    sts = read ( mf->mf_real_fd, buf, cnt );
    return sts;
  }

  memcpy(buf, &mf->mf_data [ mf->mf_offset ], mcnt );

  // adjust counters
  mf->mf_offset += mcnt;

  // done
  return mcnt;
}

// lseek
unsigned int mf_lseek ( unsigned int mf_fd, off_t offset, int flag )
{
  MF *mf = (MF *)mf_fd;

  if ( -1 != mf->mf_real_fd ) {
    unsigned int sts;

    sts = lseek( mf->mf_real_fd, offset, flag );

    mf->mf_offset = lseek ( mf->mf_real_fd, 0, SEEK_CUR );

    return sts;
  }

  switch ( flag )
    {
    case SEEK_SET:
      mf->mf_offset = offset;
      if ( mf->mf_offset > mf->mf_data_max ) {
	mf->mf_offset = mf->mf_data_max-1;
      } else {
	if ( mf->mf_offset < 0 ) {
	  mf->mf_offset = 0;
	}
      }
      break;

    case SEEK_CUR:
      mf->mf_offset += offset;
      if ( mf->mf_offset > mf->mf_data_max ) {
	mf->mf_offset = mf->mf_data_max-1;
      }
      break;

    case SEEK_END:
      mf->mf_offset = mf->st_size + offset;
      if ( mf->mf_offset < 0 ) {
	mf->mf_offset = 0;
      }
      break;
    }

  return mf->mf_offset;
}

// write
unsigned int mf_write ( unsigned int mf_fd, char *buf, int cnt )
{
  MF *mf = (MF *)mf_fd;

  if ( -1 != mf->mf_real_fd ) {
    unsigned int sts;
    sts = write ( mf->mf_real_fd, buf, cnt );
    return sts;
  }

  // is there room ???
  if ( mf->mf_offset + cnt > mf->mf_data_max ) {
    // no, make some
    int additional = max ( MF_INITIAL_SIZE, cnt );
    // TODO - write wrapper to zero data before returning to heap
    mf->mf_data = (unsigned char *)realloc ( mf->mf_data, mf->mf_offset + additional );
    assert(mf->mf_data!=NULL);
    mf->mf_data_max = mf->mf_offset + additional;
  }

  // store data
  memcpy( &mf->mf_data [ mf->mf_offset ], buf, cnt );
  // adjust offset
  mf->mf_offset += cnt;
  // adjust st_size
  if ( mf->mf_offset > mf->st_size ) {
    mf->st_size = mf->mf_offset;
  }

  // done
  return cnt;
}

// open a memory file
unsigned int mf_open ( char *name, int flags, int initial_size )
{
  MF *mf = (MF *)malloc(sizeof(MF));

  assert(mf!=NULL);
  memset(mf,0,sizeof(MF));

  if ( trace_flag > 1 )
    printf("%s: entry, name = <%s>, flags = 0x%x, initial_size = %d 0x%08x\n",
	   __FUNCTION__,
	   name,
	   flags,
	   initial_size,initial_size);

  if ( flags & O_CREAT ) {
    // a real open
    mf->mf_real_fd = open ( name, flags, initial_size );

    if ( trace_flag > 1 )
      printf("%s: mf->mf_real_fd = %d\n",
	     __FUNCTION__,
	     mf->mf_real_fd);

    return mf->mf_real_fd != -1 ? (unsigned int)mf : -1;
  } else {
    if ( 0xdeadbeef == initial_size ) {
      // a real open
      mf->mf_real_fd = open ( name, flags );

      if ( trace_flag > 1 )
	printf("%s: mf->mf_real_fd = %d\n",
	       __FUNCTION__,
	       mf->mf_real_fd);
      
      return mf->mf_real_fd != -1 ? (unsigned int)mf : -1;
    } else {
      mf->mf_real_fd = -1;
    }
  }

  if ( !initial_size ) {
    initial_size = MF_INITIAL_SIZE;
  }
  mf->mf_data = (unsigned char *)malloc(initial_size);
  assert(mf->mf_data!=NULL);
  memset(mf->mf_data,0,initial_size);
  mf->mf_data_max = initial_size;
  //mf->mf_st_size = mf->mf_offset = 0;

  // done
  return (unsigned int)mf;
}

// close a memory file
unsigned int mf_close ( unsigned int mf_fd )
{
  MF *mf = (MF *)mf_fd;

  if ( -1 != mf->mf_real_fd ) {
    if ( mf->mf_addr ) {
      munmap ( mf->mf_addr, mf->mf_len );
      mf->mf_addr = NULL;
      mf->mf_len = 0;
    }
    close(mf->mf_real_fd);
    mf->mf_real_fd = -1;

    memset(mf,0,sizeof(MF));
    free(mf);

    return 0;
  }

  if ( mf->mf_data ) {
    memset(mf->mf_data,0,mf->mf_data_max);
    free(mf->mf_data);
  }

  memset(mf,0,sizeof(MF));
  free(mf);

  // done
  return 0;
}

// fstat a memory file
unsigned int mf_fstat ( unsigned int mf_fd, struct stat *sb )
{
  MF *mf = (MF *)mf_fd;

  if ( -1 != mf->mf_real_fd ) {
    int res;
    res = fstat ( mf->mf_real_fd, sb );
    return res;
  }

  sb->st_size = mf->st_size;

  return 0;
}
