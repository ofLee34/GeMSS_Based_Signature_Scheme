LOCAL=/usr/local

HEAD=$(wildcard include/*.h)
SRC=$(wildcard src/*.c)
OBJS=$(SRC:.c=.o)

CC=gcc
LDFLAGS=-lgf2x -lkeccak -lcrypto -ldl -lpthread
# -march=native -mtune=native are used to inline functions of the gf2x library when PCLMULQDQ is available.
CFLAGS=-Wall -O2 -march=native -mtune=native -Iinclude/ -I$(LOCAL)/include -L$(LOCAL)/lib -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib

all: PQCgenKAT_sign


PQCgenKAT_sign: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) libkeccak.a
%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<


cleanKAT:
	rm -f PQCsignKAT_*.int PQCsignKAT_*.req PQCsignKAT_*.rsp

clean:
	rm -f PQCgenKAT_sign src/*.o
