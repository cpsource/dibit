Announcing dibit
----------------

Announcing 'dibit' an encryption algorithm based on bit permutations of
large variable length blocks. The demonstration program is written in 'c'
for the Linux operating system.

The code base is copyright under the Gnu Public License.

The algorithm as detailed in "Dibit Encryption Algorithm" is copyright (c)
2012, All Rights Reserved except for education, research, student, hobby, or
demonstration usage.

The demo is implemented with a key-space on the order of 2^32,000.

dibit's design goals were thus:
-------------------------------

1. Destroy Bit Locality. Bit Locality is the concept that each underlying bit
of information has a certain bit distance to the next bit of relevant 
information.

For example, if a byte were encoded to a byte, each bit couldn’t be farther
away to the next bit of information than seven bits.

With AES-128, each bit can only get a maximum distance of 127 bits away.

With dibit, a typical encryption block is around 28,000 bits, so the Bit
Locality in this case is around 28,000.

2. Don't leak any unnecessary information into the cypher-text.

This is done in a number of ways that include:

2a. Variable length bit lengths are used.
2b. The amount of clear-text bits within the block are pseudo-random, with a
pseudo-random number of pad bits added.
2c. The file name to be encrypted is obscured.
2d. The encoded bit stream is shifted pseudo-randomly within each block so you can
not determine the starting bit position.
2e. The number of '1' bits of clear-text in cypher-text can not be determined
without the key.

3. Key management is enhanced by grabbing key bits from large files commonly
available on the internet.

The core of the Dibit Encryption Algorithm works as follows:
------------------------------------------------------------

Step 1: Create a block based on some clear-text and some pad determined by a
pseudo-random number generator. The block is approximately 28,000 bits.

Step 2: For each bit in this block, another pseudo-random generator selects a
bit position.

Step 3: Next, that bit as selected in Step 2 is xor'd with a another pseudo-random bit generator.

Step 4: Next, the output bit position in the cypher-text is selected from another
pseudo-random generator.

Step 5: Finally, the results from Step 3 are placed in the cypher-text at the
location determined by Step 4.

In all, four pseudo-random number generators cooperate to drive this
algorithm.

Performance
-----------

As implemented, the algorithm encrypts about 4k bits per second.

To Install
----------

1. To build, unpack and type make.

First, install these packages in /usr/local

  libgcrypt-1.5.0.tar.bz2 
  libgpg-error-1.10.tar.bz2
  gmp-5.0.1.tar.bz2

then type

  make clean
  make depend
  make

2. dibit uses pad information as provided by file index.html. You can use
index.sh to obtain a daily copy of this file. Get the file by

  sudo sh index.sh

3. key information is provided by key_file.dat. It's a Linux soft-link and
should point to some huge file. I happen to use a Linux distribution as it's
large and commony available, but you can use anything. To get the file I use,
do

  sudo sh linux.sh

Then encrypt this file with bcrypt or some other tool to obscure it. I did it
as follows:

  rm -f key_file.dat
  bcrypt linux-2.6.32.60.tar.bz2
  ln -s linux-2.6.32.60.tar.bz2.bfe key_file.dat

Bcrypt will ask for a password. Enter one known only to you.

  - or -

  gcc -O2 -I. -o xor xor.c
  cat linux-2.6.32.60.tar.bz2 | ./xor > linux-2.6.32.60.tar.bz2.xor
  ln -s linux-2.6.32.60.tar.bz2.xor key_file.dat

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
cleartext_cnt = 1861, salt_cnt = 1214, workgroup_size = 3075, remaining_cyphertext =  3431, fuzz = 6
burried output file name <testfile.txt>
cleartext_cnt = 1985, salt_cnt = 1445, workgroup_size = 3430, remaining_cyphertext =     0, fuzz = 4
main: renamed <zzTmpdz3rl6> as <testfile.txt>

Advanced dibit
--------------

If you built the advanced dibit, you have available the '-a' switch, in which
case, the program will append the file key to the .dibit cypher-text file.
The -a takes an argument, the master key. This key is fed to AES-128/cfb, then dibit, and is used to
encrypt/decrypt the master key portion of the .dibit cypher-text file.

Example
-------

  cp README.txt testfile.txt
  export LD_LIBRARY_PATH=/usr/local/lib
  ./dibit -f testfile.txt -a "My Master Key" -k "0x0-My File Key."
  M-Key: <0x25fd6fe-My File Key.>
  We are creating output file = <zz.00001.dibit>
  cleartext_cnt = 1556, salt_cnt = 1069, workgroup_size = 2625, remaining_cleartext =  2985, fuzz = 2
  cleartext_cnt = 2385, salt_cnt = 1206, workgroup_size = 3591, remaining_cleartext =   600, fuzz = 2
  cleartext_cnt =  600, salt_cnt =  940, workgroup_size = 1540, remaining_cleartext =     0, fuzz = 1
  key_file_show_next_free: next free key_file location 0x25fe70a (39839498)

Also note that the -a switch has changed the key_file.dat offset to some
random location.

If you had added the -z switch to the command line, dibit would have removed
key_file.dat bits starting at offset 0x25fd6fe in the file. It does so by
grabbing bits at the end of the file and pasting them in here, then truncating
the file.

If you use the -z switch, you may not use M-Key to decrypt the file as key
bits in key_file.dat have been removed.


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

  dat_rnd  - the value to xor with the clear-text bit
  rnd      - the cleartext bit location
  rbit_rnd - the cyphertext bit location
  obuf     - the cyphertext output buffer
  dibuf    - the cleartext input buffer

Dibit produces an encrypted output file with the extension .dibit. There are two variants.

With the non -a variant, the .dibit file is simply cypher-text and is defined
as follows:

  (1) dibit-cyphertext = dibit ( "cleartext", -k "0x0-FileKey" )

With the -a 'master-key' flag, the dibit format changes, as it includes
all key information from above to decrypt the file. The file format is
as follows:

  (2) AES_CFB ( "dibit-cyphertext | marker | key-information | pad", master-key)

where:

  dibit-cyphertext is the results of #(1) above.

  marker is a series of unique bits to delineate between dibit-cyphertext and
  key-information

  key-information contains all the key information from -k "0x0-FileKey" and
  key_file.dat needed to decrypt dibit-cyphertext. Formally, it's built by:

    key-information = dibit ( AES_CFB( "key-data", -a "master-key" ), -a "master-key" )

  The key-data is protected first by encrypting (using -a "master-key")
  it with AES_CFB, then using dibit to encrypt this through a non key_file.dat
  variant of dibit.

  pad is just a series of 10000n bytes where n=0->15 used to bring the file
  up to a multiple of 16 bytes for the final step, the AES_CFB encryption
  of the file.

How strong is the key?
----------------------

If you run the non dash-a variant, the key-space is 2^960.

If you run the dash-a variant, the key-space is 2^32000 approximately.

Will quantum computers or DNA analysis help decrypt a message?
--------------------------------------------------------------

Possible, but certainly very costly.

Quantum computers are measured in quobits and research has them only at about
10 or so of these. This might work on a cypher with a lesser Bit Locality,
but would have trouble with the long and variable bit lengths in dibit.

DNA analysis can construct short chains of DNA/RNA on the order of 64 to 128
bits easily, but the analysis would have trouble with chains on the order of
28,000 sequences or so, as used by dibit.

Don't pseudo-random number generators all have weaknesses that can be exploited?
-------------------------------------------------------------------------------

Yes, but dibit uses two different types of pseudo-random number generators for each
of four streams. For example, the Blum Blum Shub [1] generator is XOR'd with a dual
linear feedback shift register [2][4] to produce output stream 2.

Other streams use different algorithms and are pared similarly.

Finally, all four streams are combined uniquely in the 'Dibit Encryption
Algorithm'.

Are there any repeating patters in a .dibit file?
-------------------------------------------------

None have been found so far. If you try to compress the file with gzip or bzip2,
you end up with a larger file than when you started.

Further, the .dibit file contains no 32 bit words of 0's.

Why was the final step in encryption an AES_CFB?
------------------------------------------------

This was not added to increase the strength of the encryption, but rather to obscure
the location of the marker and the number of pad bytes added.

Dibit is amazingly sensitive to workgroup-size, and the starting location of that work-group,
so this information in concealed.

Futures
-------

I can see modifying the final AES_CFB pass to make it byte oriented so that the
last AES packet in the file can't be guessed. Rarely, the pad algorithm may
write a 1 followd by 15 0's to the file. This could be guessed and used to
determine the master-key.

I can see adding a hash at the end of the file before the last AES_CFB
to watch for and detect file modifications.

The dibit code needs to be modularized with a clear and easy to use API. The
current code base written ad-hoc as the design progressed and isn't all that
modular.

References
----------

[1] http://en.wikipedia.org/wiki/Blum_Blum_Shub

[2] http://en.wikipedia.org/wiki/LFSR

[3] http://en.wikipedia.org/wiki/RSA_%28algorithm%29

[4] http://en.wikipedia.org/wiki/Shrinking_generator
