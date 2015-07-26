CC = gcc
CFLAGS = -c -g -Wall -m32 -std=c99 -O2 -I ../include
LDFLAGS = -m32

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


