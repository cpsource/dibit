Announcing dibit
----------------

Announcing 'dibit' an encryption algoritym based on bit permutations of
large variable length blocks. The demonstration program is written in 'c'
for the Linux operating system.

The code base is copyright under the Gnu Public License.

The algorithm as detailed in "Dibit Encryption Algorithm" is copyright (c)
2012, All Rights Reserved except for education, research, student, hobby, or
demonstration usage.

The demo is implemented with a keyspace on the order of 2^32,000.

dibit's design goals were thus:
-------------------------------

1. Destroy Bit Locality. Bit Locality is the concept that each underlying bit
of information has a certain bit distance to the next bit of relevant 
information.

For example, if a byte were encoded to a byte, each bit couln't be farther
away to the next bit of information than seven bits.

With AES-128, each bit can only get a maximum distance of 127 bits away.

With dibit, a typical encryption block is around 28,000 bits, so the Bit
Locality in this case is around 28,000.

2. Don't leak any unnecessary information into the ciphertext.

This is done in a number of ways that include:

2a. Variable length bit lengths are used.
2b. The amount of cleartext bits within the block are pseudo-random, with a
pseudo-random number of pad bits added.
2c. The file name to be encrypted is obsecured.
2d. The encoded bit stream is shifted pseudo-randomly within each block so you can
not determine the starting bit position.
2e. The number of '1' bits of cleartext in ciphertext can not be determined
without the key.

3. Key management is enhanced by grabbing key bits from large files commonly
available on the internet.

The core of the Dibit Encryption Algorithm works as follows:
------------------------------------------------------------

Step 1: Create a block based on some cleartext and some pad determined by a
pseudo-random number generator. The block is approximately 28,000 bits.

Step 2: For each bit in this block, another pseudo-random generator selects a
bit position.

Step 3: Next, that bit as selected in Step 2 is xor'd with a another pseudo-random bit generator.

Step 4: Next, the output bit position in the ciphertext is selected from another
pseudo-random generator.

Step 5: Finally, the results from Step 3 are placed in the ciphertext at the
location determined by Step 4.

In all, four pseudo-random number generators cooperate to drive this
algorithm.

Performance
-----------

As implemented, the algorithm encrypts about 4k bits per second.

To Install
----------

1. To build, unpack and type make.

Optionally, you can build a more complex version by first installing these
packages in /usr/local

  libgcrypt-1.5.0.tar.bz2 
  libgpg-error-1.10.tar.bz2
  gmp-5.0.1.tar.bz2
  sqlite-autoconf-3071401.tar.gz 

then type

  make clean
  make depend
  make SQL=y AES=y BBS=y LIBGCRYPT=y

2. dibit uses pad information as provided by file index.html. You can use
index.sh to obtain a daily copy of this file. Get the file by

  sudo sh index.sh

3. key information is provided by key_file.dat. It's a Linux soft-link and
should point to some huge file. I happen to use a Linux distribution as it's
large and commony available, but you can use anything. To get the file I use,
do

  sudo sh linux.sh

Tnen encrypt this file with bcrypt or some other tool to obsecure it. I did it
as follows:

  bcrypt linux-2.6.32.60.tar.bz2

Then enter some password known only to you.

To encrypt with the basic dibit
-------------------------------

  export LD_LIBRARY_PATH=/usr/local/lib
  cp README.txt testfile.txt
  ./dibit -f testfile.txt -k "0xKKKKKK-My Key."

Note: KKKKKK is the byte offset in key_file.dat. You should use a unique
offset for every file you encrypt.

Note: dibit creates consecutive files of the form zz.XXXXXX.dibit, where
XXXXXX is 0 for the first file, and 1 for the second one created - and so on.

To decrypt with the basic dibit
-------------------------------

  export LD_LIBRARY_PATH=/usr/local/lib
  ./dibit -f zz.00000.dibit -k "0xKKKKKK-My Key."

Example
-------

  Encode

> export LD_LIBRARY_PATH=/usr/local/lib
> ./dibit -f testfile.txt -k "0x0-My Test Key."
We are creating output file = <zz.00001.dibit>
cleartext_cnt = 1861, salt_cnt = 1214, workgroup_size = 3075, remaining_cleartext =  1985, fuzz = 6
cleartext_cnt = 1985, salt_cnt = 1445, workgroup_size = 3430, remaining_cleartext =     0, fuzz = 4
key_file_show_next_free: next free key_file location 0x100c (4108)

  Decode

> export LD_LIBRARY_PATH=/usr/local/lib
> ./dibit -d -f zz.00001.dibit -k "0x0-My Test Key."
main: created temp file <zzTmpdz3rl6>
cleartext_cnt = 1861, salt_cnt = 1214, workgroup_size = 3075, remaining_ciphertext =  3431, fuzz = 6
burried output file name <testfile.txt>
cleartext_cnt = 1985, salt_cnt = 1445, workgroup_size = 3430, remaining_ciphertext =     0, fuzz = 4
main: renamed <zzTmpdz3rl6> as <testfile.txt>

Advanced dibit
--------------

If you built the advanced dibit, you have available the '-m' switch, in which
case, the program will use file key_database.db to keep track of keys. -m
takes an argument, the master key. This key is fed to AES-128/cfb and is used to
encrypt/decrypt the individual file keys in the database.

Example
-------

  cp README.txt testfile.txt
  export LD_LIBRARY_PATH=/usr/local/lib
  ./dibit -f testfile.txt -m "My Master Key" -k "0x0-My File Key."
  M-Key: <0x25fd6fe-My File Key.>
  We are creating output file = <mm.00001.dibit>
  cleartext_cnt = 1556, salt_cnt = 1069, workgroup_size = 2625, remaining_cleartext =  2985, fuzz = 2
  cleartext_cnt = 2385, salt_cnt = 1206, workgroup_size = 3591, remaining_cleartext =   600, fuzz = 2
  cleartext_cnt =  600, salt_cnt =  940, workgroup_size = 1540, remaining_cleartext =     0, fuzz = 1
  key_file_show_next_free: next free key_file location 0x25fe70a (39839498)

Note that -m uses a different sequence of output files, starting with
mm.00....

Also note that the -m switch has changed the key_file.dat offset to some
random location. If you wish to decode without the -m switch, you will have to
remember this new key and keep a copy of key_file.dat.

If you had added the -z switch to the command line, dibit would have removed
key_file.dat bits starting at offset 0x25fd6fe in the file. It does so by
grabbing bits at the end of the file and pasting them in here, then truncating
the file.

If you use the -z switch, you may not use M-Key to decrypt the file as key
bits in key_file.dat have been removed.

How difficult might it be to guess the cleartext from the ciphertext?
---------------------------------------------------------------------

If each block is about 3,500 bytes, that 28000 bits. Since both imput location and
output location are pseudo-random, and the block can start anywhere in a byte,
and a bit can be either 1 or 0, you have

 2^28000

possible combinations for each block (that is, if you knew the block size,
which you don't). Computationally, this is a very difficult task.

You would have much better luck guessing at the key space, which is only
2^32,000.

Guessing is further complicated by the pad that's thrown in. Any decription
attempt would see this data as false starts and lead to confusion and
complexity. This complexity can be increased by changing the pad often,
keeping it secret, and by making the pad closer in format to the data being encripted.

Will quantum computers or DNA analysis help decript a message?
--------------------------------------------------------------

Possible, but certainly very costly.

Quantum computers are measured in quobits and research has them only at about
10 or so of these. This might work on a ciphter with a lesser Bit Locality,
but would have trouble with the long and variable bit lengths in dibit.

DNA analysis can construct short chains of DNA/RNA on the order of 64 to 128
bits easly, but the analysis would have trouble with chains on the order of
28,000 sequences or so.

Don't pseudo-random number generators all have weaknesses that can be exploited?
-------------------------------------------------------------------------------

Yes, but dibit uses two different types of pseudo-random number generators for each
stream. For example, the Blum Blum Shub [1] generator is XOR'd with a dual
linear feedback shift register [2] to produce output stream 2.

Other streams use different algorithms and are pared simmilarly.

Finally, all four streams are combined uniquely in the 'Dibit Encryption
Algorithm".

Looking under the hood.
-----------------------

Most of the 'c' code supports the basic algorithm, which can be found in
modules encrypt.c and decrypt.c.

The core of the encryption code is thus:

    	set_dibit ( obuf,
		  cache_find_rbit ( pgm_ctx->rbit_ctx, obuf, rbit_rnd),
		  cache_find_dibit( pgm_ctx->ctx, dibuf, rnd) ^ dat_rnd );

Which reads, get a random bit from the cleartext, xor it, then place it in a
random output location.

Useful variables are:

  dat_rnd  - the value to xor with the cleartext bit
  rnd      - the cleartext bit location
  rbit_rnd - the ciphertext bit location
  obuf     - the ciphertext output buffer
  dibuf    - the cleartext input buffer

References
----------

[1] http://en.wikipedia.org/wiki/Blum_Blum_Shub

[2] http://en.wikipedia.org/wiki/LFSR

[3] http://en.wikipedia.org/wiki/RSA_%28algorithm%29

This is the form of the dual lfsr used in dibit: 
  http://en.wikipedia.org/wiki/Shrinking_generator
