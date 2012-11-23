#ifndef __rabbit_h__
#define __rabbit_h__

/* Data structures */

#if !defined(ECRYPT_ctx_defined)

#define ECRYPT_ctx_defined

/* 
 * ECRYPT_ctx is the structure containing the representation of the
 * internal state of your cipher. 
 */

typedef struct
{
   u32 x[8];
   u32 c[8];
   u32 carry;
} RABBIT_ctx;

typedef struct
{
  /* 
   * Put here all state variable needed during the encryption process.
   */
   RABBIT_ctx master_ctx;
   RABBIT_ctx work_ctx;
} ECRYPT_ctx;

/*
 * Key setup. It is the user's responsibility to select the values of
 * keysize and ivsize from the set of supported values specified
 * above.
 */
void ECRYPT_keysetup(
  ECRYPT_ctx* ctx, 
  const u8* key, 
  u32 keysize,                /* Key size in bits. */ 
  u32 ivsize);                /* IV size in bits. */ 

/*
 * IV setup. After having called ECRYPT_keysetup(), the user is
 * allowed to call ECRYPT_ivsetup() different times in order to
 * encrypt/decrypt different messages with the same key but different
 * IV's.
 */
void ECRYPT_ivsetup(
  ECRYPT_ctx* ctx, 
  const u8* iv);

void ECRYPT_keystream_bytes(
  ECRYPT_ctx* ctx,
  u8* keystream,
  u32 length);                /* Length of keystream in bytes. */

#endif // ECRYPT_ctx_defined

#endif // __rabbit_h__
