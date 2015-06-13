#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "decrypt_impl.h"

extern uint8_t rodatakey[RODATALENGTH];

static int read_file(char *name, uint8_t *buf, int length)
{
	int fd;

	if((fd = open(name, O_RDONLY)) < 0) {
		perror(name);
		return -1;
	}
	if(read(fd, buf, length) != length)
		return -2;

	close(fd);
	return 0;
}

static int write_file(char *name, uint8_t *buf, int length)
{
	int fd;

	if((fd = open(name, O_CREAT|O_WRONLY, 0666)) < 0) {
		perror(name);
		return -1;
	}
	if(write(fd, buf, length) != length)
		return -2;

	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t *enc;

	if(argc != 4) {
		printf("usage: decrypt_test <enc> <rodata> <descrambled?>\n");
		return -1;
	} else {
		enc = malloc(1024);

		if(read_file(argv[1], enc, 1024) != 0)
			return -1;

		if(read_file(argv[2], rodatakey, RODATALENGTH) != 0)
			return -1;

		rodata_descramble(enc + 1);

		if(write_file(argv[3], enc, 1024) != 0)
			return -1;

		printf("wrote output to %s\n", argv[3]);
		free(enc);
		return 0;
	}

}

