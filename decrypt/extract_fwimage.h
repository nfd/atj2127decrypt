#include <inttypes.h>

#include "adfu_info.h"

int extract_fwimage_from_bytes(uint8_t *buf, char *output_dir);
int get_adfu_info(uint8_t *buf, struct adfu_info_struct *info);
