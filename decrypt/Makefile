CC ?= gcc
CFLAGS = -c -g -Wall -std=c99 -O2 -I ../include -D_DEFAULT_SOURCE
LDFLAGS = 

ifeq ($(shell uname -s),Linux)
    CFLAGS += -m32
    LDFLAGS += -m32
endif

ifeq ($(shell uname -s),Darwin)
	CFFLAGS += -arch i386
	LDFLAGS += -arch i386
endif

decrypt: decrypt_impl.o decrypt.o allocs.o extract_fwimage.o extract_brec.o
	$(CC) $(LDFLAGS) -o decrypt $+

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f *.o decrypt_test decrypt


