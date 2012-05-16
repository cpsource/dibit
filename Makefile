.SUFFIXES:
.SUFFIXES: .c .cpp .h .o .a .lr .i .d .l

CROSS_COMPILE =

CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar
STRIP=$(CROSS_COMPILE)strip
FLEX=flex
OBJDUMP=$(CROSS_COMPILE)objdump
OPT = -O2
INC = -I.
CFLAGS = $(INC) $(OPT) -Werror -Wall -gstabs+
LIBS = 

# list all source files here
CFILES = \
	cell.c \
	dibit.c \
	getkey.c \
	lfsr.c \
	scrub.c \
	cache.c \
	sha1.c \
	key_file.c \
	pgm_ctx.c \
	urandom_pseudo.c \
	mf.c \
	main.c \
	key_mgmt.c \
	debug.c \
	last_block.c

#ifeq ($(AES),y)
CFILES += aes_generic.c aes_pseudo.c aes_cfb.c
CFLAGS += -DUSE_AES
#endif

#ifeq ($(BBS),y)
CFILES += bbs_pseudo.c rsa.c
CFLAGS += -DUSE_BBS
LIBS += /usr/local/lib/libgmp.a -lm
#endif

#ifeq ($(LIBGCRYPT),y)
CFLAGS += -DUSE_LIBGCRYPT `libgcrypt-config --cflags`
LIBS += `libgcrypt-config --libs`
#endif

# turn source list into object list
OBJS = $(CFILES:%.c=%.o)

.c.o:
	$(CC) $(INC) -c $(CFLAGS) -Wno-pointer-sign $*.c

all: dibit

dibit: $(OBJS)
	$(CC) $(CFLAGS) -o dibit $(OBJS) $(LIBS)

tst: tst.c
	$(CC) $(CFLAGS) -o tst tst.c $(LIBS)

chk: chk.c mf.o
	$(CC) $(CFLAGS) -o chk chk.c mf.o $(LIBS)

aes_cfb: aes_cfb.c aes_generic.c
	$(CC) -DCP_TEST $(CFLAGS) -Wno-pointer-sign -o aes_cfb aes_cfb.c aes_generic.c $(LIBS)

last_block.o: last_block.c

main.o: main.c

debug.o: debug.c

key_mgmt.o: key_mgmt.c

aes_cfb.o: aes_cfb.c

mf.o: mf.c

rsa.o: rsa.c

urandom_pseudo.o: urandom_pseudo.c

bbs_pseudo.o: bbs_pseudo.c

aes_pseudo.o: aes_pseudo.c

aes_generic.o: aes_generic.c

sql.o: sql.c

pgm_ctx.o: pgm_ctx.c

key_file.o: key_file.c

sha1.o: sha1.c

cell.o: cell.c

dibit.o: dibit.c

getkey.o: getkey.c

lfsr.o: lfsr.c

scrub.o: scrub.c

cache.o: cache.c

# other targets

index.html:
	wget http://www.nytimes.com

depend:
	$(CC) -c $(CFLAGS) -E -MM -E -MM $(CFILES) >.depend

clean:
	rm -f *.o dibit xor tst chk
	rm -f *~
	rm -f *#

ifeq (.depend,$(wildcard .depend))
include .depend
endif
# DO NOT DELETE
