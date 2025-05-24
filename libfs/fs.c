#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

/* TODO: Phase 1 */
#define FAT_EOC 	0xFFFF
#define SIGNATURE 	"ECS150FS"
#define BLOCK_SIZE 	4096

struct superblock {
	char signature[8];
	uint16_t total_blocks;
	uint16_t root_dir_index;
	uint16_t data_start_index;
	uint16_t data_block_count;
	uint8_t fat_block_count;
	uint8_t padding[4079];
};

struct root_entry {
	char filename[FS_FILENAME_LEN];
	uint32_t file_size;
	uint16_t first_data_index;
	uint8_t padding[10];
};

static struct superblock sb;
static uint16_t *fat = NULL;
static struct root_entry root[FS_FILE_MAX_COUNT];

int fs_mount(const char *diskname) {
	if (!diskname) return -1;
	if (block_disk_open(diskname) < 0) return -1;
	//read superblock
	uint8_t sb_buf[BLOCK_SIZE];
	if (block_read(0, sb_buf) < 0) {
		block_disk_close();
		return -1;
	}
	memcpy(&sb, sb_buf, sizeof(struct superblock));
	//signature validation
	if (memcmp(sb.signature, SIGNATURE, sizeof(sb.signature)) != 0) {
		block_disk_close();
		return -1;
	}
	//block_count validation
	if ((size_t)sb.total_blocks != (size_t)block_disk_count()) {
		block_disk_close();
		return -1;
	}
	//fat_count validation
	size_t bytes_needed = (size_t)sb.data_block_count * sizeof(uint16_t);
	uint16_t expected_fat_blocks = (uint16_t)((bytes_needed + BLOCK_SIZE - 1) / BLOCK_SIZE);
	if (expected_fat_blocks != sb.fat_block_count) {
    	block_disk_close();
    	return -1;
	}
	//load fat
	fat = malloc((size_t)sb.data_block_count*BLOCK_SIZE);
	if (!fat) {
		block_disk_close();
		return -1;
	}
	//
	for (uint8_t i = 0; i < sb.fat_block_count; ++i) {
		if (block_read(1+i, (uint8_t*)fat+(i*BLOCK_SIZE)) < 0) {
			free(fat); fat = NULL;
			block_disk_close();
			return -1;
		}
	}
	//load root dir
	// root->filename = {0};
	if (block_read(sb.root_dir_index, root) < 0) {
		free(fat); fat = NULL;
		block_disk_close();
		return -1;
	}
	return 0;
}

int fs_umount(void) {
	if ( block_disk_count() == -1 ) { return -1; }

	if ( block_write(0, &sb) == -1 ) { return -1; }

	for ( int i = 0; i < sb.fat_block_count; i++ ) { 
		if ( block_write(1 + i, &fat[i]) == -1 ) { return -1; }
	}
	free(fat);
	fat = NULL;

	if ( block_write(sb.root_dir_index, &root) == -1 ) { return -1; }

	if ( block_disk_close() == -1 ) { return -1; }

	return 0;
}

int fs_info(void) {
	if ( block_disk_count() == -1 ) { return -1; } 
	//fat stats
	uint32_t fat_free_count = 0;
	for (uint32_t i = 0; i < sb.data_block_count; ++i) {
		if (fat[i] == 0) ++fat_free_count;
	}
	//root stat
	uint32_t rdir_free_count = 0;
	for (size_t i = 0; i < FS_FILE_MAX_COUNT; ++i) {
		if (root[i].filename[0] == '\0') ++rdir_free_count;
	}
	//prints
	printf("FS Info:\n");
	printf("total_blk_count=%u\n", sb.total_blocks);
	printf("fat_blk_count=%u\n", sb.fat_block_count);
	printf("rdir_blk=%u\n", sb.root_dir_index);
	printf("data_blk=%u\n", sb.data_start_index);
	printf("data_blk_count=%u\n", sb.data_block_count);
	printf("fat_free_ratio=%u/%u\n", fat_free_count, sb.data_block_count);
	printf("rdir_free_ratio=%u/%u\n", rdir_free_count, FS_FILE_MAX_COUNT);

	return 0;
}

int fs_create(const char *fulename) {

  // return -1 if disk count is empty
  if ( block_disk_count() == -1 ) return -1;  

  // if len is > 16, return -1
  if ( strlen(filename) > FS_FILENAME_LEN ) {
    return -1;
  }

  for ( int i = 0; i < FS_FILE_MAX_COUNT; i++ ) {
    if ( root[i].filename == NULL ) {
      root[i].filename = malloc(sizeof(char) * strlen(filename));
      root[i].filename = filename;
      root[i].filesize = 0;
      // do FAT_EOC thing later
      return 0;
    }
  }

  // return since there is no empty roots
  return -1;

}

int fs_delete(const char *filename) {
	/* TODO: Phase 2 */
}

int fs_ls(void) {
	/* TODO: Phase 2 */
}

int fs_open(const char *filename) {
	/* TODO: Phase 3 */
}

int fs_close(int fd) {
	/* TODO: Phase 3 */
}

int fs_stat(int fd) {
	/* TODO: Phase 3 */
}

int fs_lseek(int fd, size_t offset) {
	/* TODO: Phase 3 */
}

int fs_write(int fd, void *buf, size_t count) {
	/* TODO: Phase 4 */
}

int fs_read(int fd, void *buf, size_t count) {
	/* TODO: Phase 4 */
}
