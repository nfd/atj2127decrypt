#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdbool.h>
#include <ctype.h>

#include "decrypt_impl.h"
#include "extract_fwimage.h"
#include "extract_brec.h"

#include "ucos-structs.h"
#include "adfu_info.h"

/* Files to look for in the firmware image */
const uint8_t fwimage_key_name[] = "FWIMAGE FW ";
const uint8_t nandid_key_name[] = "FLASH_IDBIN";

/* Assembly-language routines */
//extern int func_fw_decrypt_init(struct decrypt_struct *);
//extern void func_fw_decrypt_run(uint8_t *buf_out, int length, uint8_t *crypt);

#if 0
static void dump_buffer(char *filename, uint8_t *buf, int length)
{
	int fd;
	fd = open(filename, O_CREAT|O_WRONLY, 0666);
	write(fd, buf, length);
	close(fd);
}

/* Locate a file in an AFI directory (index of files in the upgrade file) */
static int
find_afi_dir_key(uint8_t *buffer, uint32_t buffer_len, const uint8_t *name, uint8_t key_len, AFI_DIR_t *dest)
{
	AFI_DIR_t *current;
	AFI_DIR_t *end = (AFI_DIR_t *)(buffer + buffer_len);

	for(current = (AFI_DIR_t *)buffer; current < end; current++)
    {
        if (memcmp(current->name, name, key_len) == 0) {
			memcpy(dest, current, sizeof(*current));
			return 0;
        }
    }

	return -1;
}
#endif


typedef int(write_file_callback)(uint8_t *, size_t, void*);

struct write_file_to_disk_callback_data {
	int fd;
};

struct write_file_to_buffer_callback_data {
	int idx;
	uint8_t *buffer;
};

static int
read_and_decrypt(struct decrypt_struct *decrypt_info, int fd, uint8_t *buffer, int length)
{
	uint32_t read_bytes;

	while(length) {
		if(length > 2048)
			read_bytes = 2048;
		else
			read_bytes = length;

		int amt_read = read(fd, decrypt_info->pInOutBuffer, read_bytes);
		if(amt_read != read_bytes) {
			printf("amt read %d read bytes %d length %d\n", amt_read, read_bytes, length);
			perror("read_and_decrypt: read");
			return -1;
		}

		func_fw_decrypt_run_c(decrypt_info->pInOutBuffer, read_bytes, decrypt_info->pGLBuffer);

		memcpy(buffer, decrypt_info->pInOutBuffer, read_bytes);

		length -= read_bytes;
		buffer += read_bytes;
	}

	return 0;
}

#define WRITE_BUFFER_SIZE (16 * 1024)
static int
firmware_file_write(struct decrypt_struct *decrypt_info, int fd, write_file_callback *cb, void *cb_data, uint32_t fw_offset, uint32_t fw_length)
{
	uint8_t *data_buffer; /* Scratch memory */
	size_t buffer_length = WRITE_BUFFER_SIZE < fw_length ? WRITE_BUFFER_SIZE : fw_length;

	data_buffer = malloc(buffer_length);
	if(!data_buffer) {
		perror("Couldn't allocate scratch\n");
		return -1;
	}

	lseek(fd, fw_offset, SEEK_SET);

    while (fw_length) {
		size_t chunk_size = WRITE_BUFFER_SIZE < fw_length ? WRITE_BUFFER_SIZE : fw_length;

		if(read_and_decrypt(decrypt_info, fd, data_buffer, chunk_size) != 0) {
			printf("firmware_file_write: read_and_decrypt in loop\n");
			free(data_buffer);
			return -1;
		}

		if((*cb)(data_buffer, chunk_size, cb_data) != 0) {
			printf("firmware_file_write: write in loop\n");
			free(data_buffer);
			return -1;
		}

		fw_length -= chunk_size;
    }

	free(data_buffer);
    return 0;
}

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
write_file_to_disk_callback(uint8_t *data, size_t size, void *cb_data)
{
	int fd_out = ((struct write_file_to_disk_callback_data *)cb_data)->fd;

	if(write(fd_out, data, size) != size)
		return -1;

	return 0;
}

static int
write_file_to_disk(struct decrypt_struct *decrypt_info, int fd, char *output_dir, uint32_t firmware_base, AFI_DIR_t *direntry)
{
	char filename[8 + 3 + 2]; // max 8 character name, 3 character stem, a dot, and a \0.
	char pathname[256];
	struct write_file_to_disk_callback_data cb_data;

	make_sensible_direntry_filename(direntry, filename);

	if(snprintf(pathname, 256, "%s/%s", output_dir, filename) > 255) {
		printf("Pathname too long");
		return -1;
	}

	int fd_out = open(pathname, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if(fd_out < 0) {
		perror("open fd_out");
		return -1;
	}

	/*printf("AFI dir entry: type %d, address %x, offset %x, length %x, sub_type %x, checksum %x\n",
			direntry->type, direntry->address, direntry->offset, direntry->length, direntry->sub_type,
			direntry->checksum);
			*/

	printf("Writing %s (type %c, length %d)\n", filename, direntry->type, direntry->length);

	cb_data.fd = fd_out;

	firmware_file_write(decrypt_info, fd, &write_file_to_disk_callback, &cb_data, firmware_base + direntry->offset, direntry->length);
	close(fd_out);
	return 0;
}

static int
write_file_to_buffer_callback(uint8_t *data, size_t size, void *v_cb_data)
{
	struct write_file_to_buffer_callback_data *cb_data = v_cb_data;

	memcpy(cb_data->buffer + cb_data->idx, data, size);
	cb_data->idx += size;

	return 0;
}

static uint8_t *
write_file_to_buffer(struct decrypt_struct *decrypt_info, int fd, char *output_dir, uint32_t firmware_base, AFI_DIR_t *direntry)
{
	struct write_file_to_buffer_callback_data cb_data;

	cb_data.buffer = malloc(direntry->length);
	cb_data.idx = 0;

	firmware_file_write(decrypt_info, fd, write_file_to_buffer_callback, &cb_data, firmware_base + direntry->offset, direntry->length);

	return cb_data.buffer;
}

static int dump_single_file(struct decrypt_struct *decrypt_info, int fd, char *output_dir, uint32_t firmware_base, AFI_DIR_t *current, bool split, struct adfu_info *info)
{
	bool write_to_disk = true;

	if(split) {
		if (memcmp(current->name, "FWIMAGE FW ", 11) == 0) {
			uint8_t *data = write_file_to_buffer(decrypt_info, fd, output_dir, firmware_base, current);

			extract_fwimage_from_bytes(data, output_dir);

			if(info)
				get_adfu_info(data, info);

			free(data);
			write_to_disk = false;
		}

		if (memcmp(current->name, "BRECF650BIN", 11) == 0) { /* TODO: no particular reason to use this one */
			uint8_t *data = write_file_to_buffer(decrypt_info, fd, output_dir, firmware_base, current);

			split_brec_bytes(data, output_dir);

			free(data);

			// Write brec to disk anyway
		}

	}

	
	if(write_to_disk) {
		write_file_to_disk(decrypt_info, fd, output_dir, firmware_base, current);
	}

	return 0;
}

static int
do_dump(struct decrypt_struct *decrypt_info, int fd, char *output_dir, bool split, struct adfu_info *info)
{
	int ret;
	uint32_t firmware_base;
	ret = read(fd, decrypt_info->pInOutBuffer, DECRYPT_INOUT_LENGTH);

	if(ret != DECRYPT_INOUT_LENGTH) {
		fprintf(stderr, "do_dump: read fail\n");
		return -1;
	}

	ret = func_fw_decrypt_init_c(decrypt_info);
	if(ret != 0) {
		printf("Firmware failed validity checks (%d)\n", ret);
		return ret;
	}

	firmware_base = DECRYPT_INOUT_LENGTH - decrypt_info->InOutLen;
	//printf("firmware offset %x\n", firmware_base);  // Always 0x800?
	//dump_buffer("inital_decrypt.bin", decrypt_info->pInOutBuffer, DECRYPT_INOUT_LENGTH );
	
	// The decryption gives us a mapping of files to offsets. 
	// Count the number of directory entries and store them somewhere.
	int num_entries = 0;
	for(AFI_DIR_t *current = (AFI_DIR_t *)decrypt_info->pInOutBuffer; current->name[0] != 0; current++)
		num_entries ++;

	AFI_DIR_t *directory = malloc(sizeof(AFI_DIR_t) * num_entries);
	if(directory == NULL) {
		perror("malloc central directory\n");
		return -1;
	}
	memcpy(directory, decrypt_info->pInOutBuffer, sizeof(AFI_DIR_t) * num_entries);

	// TODO: First entry seems to be a signature of sorts rather than a file
	for(int entry_idx = 1; entry_idx < num_entries; entry_idx++) {
		AFI_DIR_t *current = &directory[entry_idx];
		dump_single_file(decrypt_info, fd, output_dir, firmware_base, current, split, info);
	}

	free(directory);

	return 0;
}

static int 
write_adfu_info(char *output_dir, struct adfu_info *info)
{
	char pathname[1024];
	FILE *info_file;

	sprintf(pathname, "%s/adfu_info.json", output_dir);

	info_file = fopen(pathname, "w");

	fprintf(info_file, "{\"fwimage\":{\n");
	fprintf(info_file, "	\"sdk_description\": \"%s\",\n", info->sdk_description);
	fprintf(info_file, "	\"INF_USERDEFINED_ID_48\": \"%.48s\",\n", info->usb_setup_info);
	fprintf(info_file, "	\"SDK_VER\": \"%.4s\",\n", info->sdk_ver);
	fprintf(info_file, "	\"files\":[");

	for(int filename_idx=0; filename_idx < info->num_files; filename_idx++) {
		char filename[13];
		int new_fn_idx, old_fn_idx;

		for(new_fn_idx = old_fn_idx = 0; old_fn_idx < 11; old_fn_idx ++) {
			char c = info->filename[filename_idx][old_fn_idx];
			if(c != ' ')
				filename[new_fn_idx++] = tolower(c);

			if(old_fn_idx == 7)
				filename[new_fn_idx++] = '.';
		}

		filename[new_fn_idx++] = '\0';

		fprintf(info_file, "\"%s\"", filename);

		if(filename_idx < info->num_files - 1) {
			fprintf(info_file, ", ");
		}
	}

	fprintf(info_file, "]}\n}\n");

	fclose(info_file);

	return 0;
}

int dump_firmware(char *filename_in, char *output_dir, bool split, bool dfuscript)
{
	struct stat stat_buf;
	struct decrypt_struct decrypt_info;
	struct adfu_info info;
	int fd_in;

	if(stat(filename_in, &stat_buf) != 0) {
		perror("stat");
		return -1;
	}

	memset((void *)&decrypt_info, '\0', sizeof(decrypt_info));

	decrypt_info.pInOutBuffer = malloc(DECRYPT_INOUT_LENGTH);
	decrypt_info.InOutLen = DECRYPT_INOUT_LENGTH;
	decrypt_info.FileLength = stat_buf.st_size;
	decrypt_info.pGLBuffer = malloc(sizeof(struct GLBuffer));
	decrypt_info.initusebuffer = malloc(DECRYPT_INIT_LENGTH);
	decrypt_info.initusebufferlen = DECRYPT_INIT_LENGTH;

	/* Create output directory */
	if(access(output_dir, W_OK) != -1) {
		//printf("Output directory %s already exists. Exiting without doing anything\n", output_dir);
		//return -1;
		printf("Output directory %s exists and its contents will be overwritten.\n", output_dir);
	} else {
		if(mkdir(output_dir, 0777) != 0) {
			perror("mkdir");
			return -1;
		}
	}

	fd_in = open(filename_in, O_RDONLY);
	if(fd_in < 0) {
		perror("fd_in");
		return -1;
	}

	if(do_dump(&decrypt_info, fd_in, output_dir, split, dfuscript? &info : NULL) != 0) {
		fprintf(stderr, "do_upgrade fail\n");
		return -1;
	}

	if(dfuscript)
		write_adfu_info(output_dir, &info);

	free(decrypt_info.pInOutBuffer);
	free(decrypt_info.pGLBuffer);
	free(decrypt_info.initusebuffer);

	return 0;
}

const struct option longopts[] = {
	{"split", no_argument, NULL, 's'},
	{"dfu", no_argument, NULL, 'd'},
	{"help", no_argument, NULL, 'h'}
};

static void show_help() {
	printf("decrypt [options] filename [outdir] -- decrypt an Actions UPGRADE.HEX file\n");
	printf("\n");
	printf(" filename  : an UPGRADE.HEX file\n");
	printf(" outdir    : output directory (default: 'out')\n");
	printf("   --split : Split BREC and FWIMAGE into component parts\n");
	printf("   --dfu   : Produce an ADFU upgrade script (implies --split)\n");
	printf("   --help  : Show this message\n");
}


int main(int argc, char **argv)
{
	int arg;

	bool split_fw = false;
	bool make_dfuscript = false;

	while((arg = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch(arg) {
			case 's':
				split_fw = true;
				break;
			case 'd':
				make_dfuscript = split_fw = true;
				break;
			case 'h':
				show_help();
				return 1;
			default:
				printf("Option %c not implemented\n", arg);
				return 1;
		};
	}

	argc -= optind;
	argv += optind;

	if(0 == argc) {
		show_help();
		return 1;
	}

	char *fw_filename = argv[0];
	char *outdir = "out";

	if(argc > 1)
		outdir = argv[1];

	return dump_firmware(fw_filename, outdir, split_fw, make_dfuscript);
}

