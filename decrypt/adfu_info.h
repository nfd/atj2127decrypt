#ifndef ADFU_INFO_H
#define ADFU_INFO_H

struct adfu_info {
	uint8_t sdk_ver[4];					/* LFI + 4 */
	uint8_t usb_setup_info[48];			/* LFI + 80 */
	uint8_t sdk_description[336];		/* LFI + 128 */
	int num_files;
	char filename[240][11];
};

#endif

