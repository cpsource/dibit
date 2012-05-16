#ifndef __key_mgmt_h__
#define __key_mgmt_h__

struct pgm_ctx_struct_t;
struct dibit_file_struct_t;

// get key from somewhere, based on command line swiches
void key_mgmt_get_key ( struct pgm_ctx_struct_t*pgm_ctx,
			char **ck_flag,
			char **ca_flag,
			unsigned int fd_in,
			struct dibit_file_struct_t *dfs,
			char *argv0 );


#endif // __key_mgmt_h__
