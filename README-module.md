# Module Descriptions

This document briefly describes the purpose of each source file in the project.

- `aes_cfb.c` - AES encryption in CFB mode
- `aes_generic.c` - Generic AES helper functions
- `aes_pseudo.c` - AES-based pseudo random generator
- `bbs_pseudo.c` - Blum Blum Shub pseudo random generator
- `cache.c` - Bit caching utilities
- `cell.c` - Cell based pseudo random support
- `debug.c` - Debugging helpers
- `decrypt.c` - Core decryption routine
- `dibit.c` - Command line interface and main processing
- `diffuser.c` - Data diffusion implementation
- `encrypt.c` - Core encryption routine
- `getkey.c` - Command line key extraction
- `key_file.c` - Key file management
- `key_mgmt.c` - High level key management
- `last_block.c` - Obscure final AES block
- `lfsr.c` - Linear feedback shift register routines
- `main.c` - Small wrapper for dibit
- `mf.c` - In-memory file abstraction
- `pgm_ctx.c` - Program context management
- `prime_table.c` - Prime number table builder
- `rabbit.c` - Rabbit stream cipher
- `rsa.c` - Simple RSA helper code
- `scrub.c` - Secure file wiping utilities
- `sha1.c` - SHA1 hash implementation
- `trivium.c` - Trivium stream cipher
- `urandom_pseudo.c` - PRNG based on /dev/urandom
- `util.c` - Basic bit manipulation helpers
- `wabbit.c` - Rabbit + LFSR file processing
- `xor.c` - Utility for XOR operations
