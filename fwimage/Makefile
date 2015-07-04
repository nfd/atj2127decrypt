CC = gcc
CFLAGS = -c -g -Wall -m32 -std=c99 -O2 -I ../include
LDFLAGS = -m32

ifeq ($(shell uname -s),Darwin)
	CFFLAGS += -arch i386
	LDFLAGS += -arch i386
endif

extract: extract.o allocs.o
	$(CC) $(LDFLAGS) -o extract $+

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f *.o extract


