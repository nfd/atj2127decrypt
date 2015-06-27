CC = gcc
CFLAGS = -c -g -Wall -m32 -std=c99 -O2
LDFLAGS = -m32

ifeq ($(shell uname -s),Darwin)
	CFFLAGS += -arch i386
	LDFLAGS += -arch i386
endif

decrypt: decrypt_impl.o decrypt.o
	$(CC) $(LDFLAGS) -o decrypt $+

decrypt_test: decrypt_impl.o decrypt_test.o
	$(CC) $(LDFLAGS) -o decrypt_test $+

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f *.o decrypt_test decrypt


