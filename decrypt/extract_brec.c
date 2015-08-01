#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>

#define WELCOME_BIN_START_LOCATION 4096 /* offset inside brec */
#define WELCOME_BIN_LENGTH 16384 /* This is the maximum length. The actual length isn't stored. */
#define SECTOR_SIZE 512
#define MAX_PATHNAME 1024

struct brec_info {
	uint8_t unknown[12];
	uint16_t brec_length_sectors;
	uint16_t resources_length_sectors;
};

static int
write_brec_portion(char *output_dir, char *filename, uint8_t *data, size_t length)
{
	char pathname[MAX_PATHNAME];

	if(snprintf(pathname, MAX_PATHNAME, "%s/%s", output_dir, filename) >= (MAX_PATHNAME - 1)) {
		fprintf(stderr, "Pathname too long\n");
		return 1;
	}

	int handle = open(pathname, O_CREAT | O_WRONLY, 0666);
	if(handle < 0) {
		fprintf(stderr, "Couldn't open %s: %s\n", pathname, strerror(errno));
		return -1;
	}

	if(write(handle, data, length) != length) {
		fprintf(stderr, "Couldn't write %s: %s\n", pathname, strerror(errno));
		return -1;
	}

	return 0;
}

int split_brec_bytes(uint8_t *brec_bytes, char *output_dir, char *flash_type)
{
	char filename[256];

	struct brec_info *info = (void *)brec_bytes;

	size_t brec_length = info->brec_length_sectors * SECTOR_SIZE;
	size_t resources_start = brec_length;
	size_t resources_length = info->resources_length_sectors * SECTOR_SIZE;

	sprintf(filename, "brec%s.bin", flash_type);
	write_brec_portion(output_dir, filename, brec_bytes, brec_length);

	sprintf(filename, "welcome%s.bin", flash_type);
	write_brec_portion(output_dir, filename, brec_bytes + WELCOME_BIN_START_LOCATION, WELCOME_BIN_LENGTH);

	sprintf(filename, "welcome%s.res", flash_type);
	write_brec_portion(output_dir, filename, brec_bytes + resources_start, resources_length);

	return 0;
}

