#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>

#include "ucos-structs.h"
#include "adfu_info.h"

#define FW_CENTRAL_DIRECTORY_OFFSET 0x200
#define MAX_PATHNAME 1024

/* TODO: put this in a library */
static void
make_sensible_direntry_filename(AFI_DIR_t *direntry, char *out)
{
	for(int i=0; i < 8; i++) {
		if(direntry->name[i] == ' ')
			break;
		*out++ = tolower(direntry->name[i]);
	}

	*out++ = '.';

	for(int i=0; i < 3; i++) {
		if(direntry->name[i + 8] == ' ')
			break;
		*out++ = tolower(direntry->name[i + 8]);
	}

	*out++ = 0;
}


static int
write_buf_to_file(uint8_t *buf, size_t length, char *pathname)
{
	int handle = open(pathname, O_CREAT | O_WRONLY, 0666);
	if(handle < 0) {
		fprintf(stderr, "Couldn't open %s: %s\n", pathname, strerror(errno));
		return -1;
	}

	if(write(handle, buf, length) != length) {
		fprintf(stderr, "Couldn't write %s: %s\n", pathname, strerror(errno));
		return -1;
	}

	return 0;
}

int
extract_fwimage_from_bytes(uint8_t *buf, char *output_dir)
{
	char *entry_filename, *entry_pathname;

	if((entry_filename = malloc( 8 + 3 + 2 )) == NULL) {
		fprintf(stderr, "Couldn't alloc\n");
		return -1;
	}

	if((entry_pathname = malloc(MAX_PATHNAME)) == NULL) {
		fprintf(stderr, "Couldn't alloc\n");
		free(entry_filename);
		return -1;
	}

	AFI_DIR_t *entry = (AFI_DIR_t *)(&buf[FW_CENTRAL_DIRECTORY_OFFSET]);

	for(; entry->name[0]; entry++) {
		make_sensible_direntry_filename(entry, entry_filename);
		if(snprintf(entry_pathname, MAX_PATHNAME, "%s/%s", output_dir, entry_filename) >= (MAX_PATHNAME - 1)) {
			fprintf(stderr, "Pathname too long\n");
		} else {
			printf("Writing %s\n", entry_filename);
			write_buf_to_file(&buf[entry->offset * 512], entry->length, entry_pathname);
		}
	}

	free(entry_pathname);
	free(entry_filename);
	return 0;
}

int
get_adfu_info(uint8_t *buf, struct adfu_info_struct *info)
{
	uint32_t r3_config_offset;

	/* TODO get LFI_Head_t in here */
	memcpy(info->sdk_ver, buf + 4, 4);
	memcpy(info->usb_setup_info, buf + 80, 48);
	memcpy(info->sdk_description, buf + 128, 336);

	memcpy(&r3_config_offset, buf + 506, 4);

	if(r3_config_offset == 0)
		info->r3_config_filename_idx = -1;

	AFI_DIR_t *entry = (AFI_DIR_t *)(&buf[FW_CENTRAL_DIRECTORY_OFFSET]);
	int idx = 0;

	for(idx = 0; entry->name[0]; entry++, idx++) {
		memcpy(info->filename[idx], entry->name, 11);

		if(r3_config_offset == entry->offset)
			info->r3_config_filename_idx = idx;
	}

	info->num_files = idx;

	return 0;
}

int
extract_fwimage_from_file(char *filename, char *output_dir)
{
	struct stat thestat;
	uint8_t *buf;

	if (lstat(filename, &thestat) == -1) {
		fprintf(stderr, "Couldn't stat %s: %s\n", filename, strerror(errno));
		return -1;
	}
	
	buf = malloc(thestat.st_size);
	if(buf == NULL) {
		fprintf(stderr, "Couldn't allocate memory\n");
		return -1;
	}

	int handle = open(filename, O_RDONLY);

	if(handle == -1) {
		fprintf(stderr, "Couldn't open %s: %s\n", filename, strerror(errno));
		free(buf);
		return -1;
	}

	if(read(handle, buf, thestat.st_size) != thestat.st_size) {
		fprintf(stderr, "Couldn't read %s: %s\n", filename, strerror(errno));
		close(handle);
		free(buf);
		return -1;
	}
	close(handle);

	int extract_result = extract_fwimage_from_bytes(buf, output_dir);

	free(buf);
	return extract_result;
}

