#
# Simple shared library makefile by Sam Tobin-Hochstadt, 2013
# 
#

CC = gcc
LD = $(CC)
RM = rm -f
CFLAGS = -W -Wall -Wbad-function-cast -Wcast-align -Wcast-qual -Wmissing-prototypes \
         -Wstrict-prototypes -Wshadow -Wundef -Wpointer-arith -O2 -fomit-frame-pointer \
         -funroll-loops -DNO_BF_ASM -fPIC

SRCDIR = crypt_blowfish-1.2

OBJS = crypt_blowfish.o crypt_gensalt.o wrapper.o

libcrypt_blowfish.so: $(OBJS)
	$(LD) -shared -o libcrypt_blowfish.so $(OBJS)

crypt_blowfish.o: crypt_blowfish.h
crypt_gensalt.o: crypt_gensalt.h
wrapper.o: ow-crypt.h

wrapper.c: 
	cp $(SRCDIR)/$*.c .
crypt_blowfish.c: 
	cp $(SRCDIR)/$*.c .
crypt_gensalt.c:
	cp $(SRCDIR)/$*.c .
ow-crypt.h:
	cp $(SRCDIR)/$*.h .
crypt_blowfish.h:
	cp $(SRCDIR)/$*.h .
crypt_gensalt.h:
	cp $(SRCDIR)/$*.h .

.c.o:
	$(CC) -c $(CFLAGS) $*.c

clean:
	$(RM) $(LIB) *.o *.c *.h
