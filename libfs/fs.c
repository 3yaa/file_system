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

struct open_file {
	int on; //0|1
	uint8_t root_index;
	uint32_t file_offset;
};

struct root_entry {
	char filename[FS_FILENAME_LEN];
	uint32_t fileSize;
	uint16_t first_data_index;
	uint8_t padding[10];
};

static struct superblock sb;
static uint16_t *fat = NULL;
static struct root_entry root[FS_FILE_MAX_COUNT];
static struct open_file fd_table[FS_OPEN_MAX_COUNT];

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

// might have to do datablock stuff
int fs_create(const char *filename) {
	// return -1 if disk count is empty
	if ( block_disk_count() == -1 ) return -1;  
	// invalid filename
	if ( !filename ) return -1;
  	// if len is > 16, return -1
  	if ( strlen(filename) >= FS_FILENAME_LEN ) return -1;

	// @index: index of first free file
	int index = FS_FILE_MAX_COUNT;
  	for ( int i = 0; i < FS_FILE_MAX_COUNT; i++ ) {
    	if ( strcmp(root[i].filename, filename) == 0 ) {
			return -1; //filename alrdy exists
		}
		if ( root[i].filename[0] == '\0' && i < index) {
			index = i;
		}
	}
	if ( index -= FS_FILE_MAX_COUNT ) return -1; //max_file in root alrdy
	//
	strncpy(root[index].filename, filename, FS_FILENAME_LEN-1);
	root[index].filename[FS_FILENAME_LEN-1] = '\0';
	root[index].fileSize = 0;
	root[index].first_data_index = FAT_EOC; 
	return 0; 
}

int fs_delete(const char *filename) {
	// check if disk count exists
	if ( block_disk_count() == -1 ) return -1;
	// if the file name is > 16, invalid filename
	if ( strlen(filename) >= FS_FILENAME_LEN ) return -1;

	for ( int i = 0; i < FS_FILE_MAX_COUNT; i++ ) {
		if ( memcmp(root[i].filename, filename, strlen(filename)) == 0 ) {
			root[i].filename[0] = '\0'; // might have to set other indicies to '\0' as well 
			root[i].fileSize = 0;
			root[i].first_data_index = FAT_EOC; 
			return 0;
		}
	}
	return -1;
}

int fs_ls(void) {
	if ( block_disk_count() == -1 ) return -1;

	printf("FS Ls:\n");
	for ( int i = 0; i < FS_FILE_MAX_COUNT; i++ ) {
		if ( root[i].filename != NULL ) {
			printf("file: %s, ", root[i].filename);
			printf("size: %u, ", root[i].fileSize);
			printf("data_black: %u\n", root[i].first_data_index);
		}
	}
	return 0;
}

int fs_open(const char *filename) {
	if (block_disk_count() == -1) return -1; //not mounted
	if (!filename) return -1; //no filename
	if (strlen(filename) >= FS_FILENAME_LEN) return -1; //invalid filename-size
	//check for open fd
	for (size_t i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (memcmp(root[i].filename, filename, sizeof(filename)) != 0) continue;
		for (size_t j = 0; j < FS_OPEN_MAX_COUNT; j++) {
			if (!fd_table[j].on) {
				fd_table[j].on = 1;
				fd_table[j].root_index = i;
				fd_table[j].file_offset = 0;
				return j;
			}
		}
		return -1; //fd_table full
	}
	return -1; //invalid filename-DNE
}

int fs_close(int fd) {
	if (block_disk_count() == -1) return -1; //not mounted
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) return -1; //invlaid fd-out_bound
	if (!fd_table[fd].on) return -1; //invalid fd-not in use
	//close
	fd_table[fd].on = 0;
	fd_table[fd].file_offset = 0;
	return 0;
}

int fs_stat(int fd) {
	if (block_disk_count() == -1) return -1; //not mounted
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) return -1; //invlaid fd-out_bound
	if (!fd_table[fd].on) return -1; //invalid fd-not in use
	//
	return root[fd_table[fd].root_index].fileSize;
}

int fs_lseek(int fd, size_t offset) {
	if (block_disk_count() == -1) return -1; //not mounted
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) return -1; //invlaid fd-out_bound
	if (!fd_table[fd].on) return -1; //invalid fd-not in use
	if (offset > fs_stat(fd)) return -1; //offset > file_size
	//
	fd_table[fd].file_offset = offset;
	return 0;
}

int fs_write(int fd, void *buf, size_t count) {
    if (block_disk_count() == -1) return -1; // not mounted
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) return -1; //invlaid fd-out_bound
	if (!fd_table[fd].on) return -1; //invalid fd-not in use
	if (!buf) return -1; // buffer is empty
	if (count < 0) return -1;
	/* TODO: Phase 4 */
	return 0;
}

int resize(void **buf, size_t new_bytes) {
	void *temp = realloc(buf, new_bytes);
	if (!temp) {
		free(buf);
		buf = NULL;
		return -1;
	}
	*buf = temp;
	return 0;
}

size_t find_eoc(const uint8_t *buf) {
	size_t i = 0;
	while (memcmp(buf[i], FAT_EOC, sizeof(FAT_EOC) != 0)) {
		i++;
	}
	return i;
}

int fs_read(int fd, void *buf, size_t count) {
	if (block_disk_count() == -1) return -1; //not mounted
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) return -1; //invlaid fd-out_bound
	if (!fd_table[fd].on) return -1; //invalid fd-not in use
	if (!buf) return -1; //invalid buf
	if (count <= 0) return -1;
	//
	struct root_entry *re = &root[fd_table[fd].root_index];
	size_t start = fd_table[fd].file_offset;
	size_t end = count;
	size_t file_size = fs_stat(fd);
	//
	if (start + end > fs_stat(fd)) {
		end = fs_stat(fd) - start;
	}

	uint8_t *bounced_buf = NULL;
	bounced_buf = malloc(BLOCK_SIZE*sizeof(uint8_t));
	for (size_t i = 0; own_count < count; i++) {
		block_read(1+i, bounced_buf);
		own_count += BLOCK_SIZE;
		if (resize((void**)&bounced_buf, BLOCK_SIZE) < 0) return -1; //alloc fail
	}
	//
	if (memcpy(buf, bounced_buf+start, (end-start)*sizeof(uint8_t)) != 0) return -1;
	
	return (end - start); // return number of bytes read		
}