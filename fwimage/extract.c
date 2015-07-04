#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "ucos-structs.h"
#include "allocs.h"

#define FW_CENTRAL_DIRECTORY_OFFSET 0x200
#define MAX_PATHNAME 1024

static struct option longopts[] = {
	{ "output", required_argument, NULL, 'o'},
	{ "help", no_argument, NULL, 'h'},
	{0, 0, 0, 0}
};

int new_string(char **dest, char *src)
{
	*dest = pool_alloc(strlen(src) + 1);
	if(!(*dest)) 
		return -1;

	strcpy(*dest, src);
	return 0;
}

/* TODO: put this in a library */
static void
make_sensible_direntry_filename(AFI_DIR_t *direntry, char *out)
{
	for(int i=0; i < 8; i++) {
		if(direntry->name[i] == ' ')
			break;
		*out++ = direntry->name[i];
	}

	*out++ = '.';

	for(int i=0; i < 3; i++) {
		if(direntry->name[i + 8] == ' ')
			break;
		*out++ = direntry->name[i + 8];
	}

	*out++ = 0;
}


int write_buf_to_file(uint8_t *buf, size_t length, char *pathname)
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

int extract(char *filename, char *output_dir)
{
	struct stat thestat;
	uint8_t *buf;
	char *entry_filename, *entry_pathname;

	if((entry_filename = pool_alloc( 8 + 3 + 2 )) == NULL) {
		fprintf(stderr, "Couldn't alloc\n");
		return -1;
	}

	if((entry_pathname = pool_alloc(MAX_PATHNAME)) == NULL) {
		fprintf(stderr, "Couldn't alloc\n");
		return -1;
	}

	if (lstat(filename, &thestat) == -1) {
		fprintf(stderr, "Couldn't stat %s: %s\n", filename, strerror(errno));
		return -1;
	}
	
	buf = pool_alloc(thestat.st_size);
	if(buf == NULL) {
		fprintf(stderr, "Couldn't allocate memory\n");
		return -1;
	}

	int handle = open(filename, O_RDONLY);

	if(handle == -1) {
		fprintf(stderr, "Couldn't open %s: %s\n", filename, strerror(errno));
		return -1;
	}

	if(read(handle, buf, thestat.st_size) != thestat.st_size) {
		fprintf(stderr, "Couldn't read %s: %s\n", filename, strerror(errno));
		close(handle);
		return -1;
	}

	close(handle);

	mkdir(output_dir, 0777);

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
	return 0;
}

static void print_help(void)
{
	printf("Usage: extract [--output DIR] filename.fw\n");
}

int main(int argc, char **argv)
{
	char *output_dir = NULL;
	int opt;

	pool_init();

	while((opt = getopt_long(argc, argv, "o:h", longopts, NULL)) != -1) {
		switch(opt) {
		case 'o':
			if(new_string(&output_dir, optarg))
				return 1;
			break;
		case 'h':
			print_help();
			return 0;
		}
	}

	argc -= optind;
	argv += optind;

	if(!argc) {
		print_help();
		return 1;
	}

	if(output_dir == NULL)
		if(new_string(&output_dir, "out"))
			return 1;

	pool_push();
	extract(argv[0], output_dir);
	pool_pop();
	
	return 0;

}

