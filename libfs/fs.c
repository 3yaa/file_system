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
	// fat = calloc((size_t)sb.data_block_count, sizeof(uint16_t));
	fat = calloc((size_t)sb.fat_block_count * BLOCK_SIZE, 1);
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
		if (block_write(1+i, (uint8_t*)fat+(i*BLOCK_SIZE)) == -1) return -1;
	}

	free(fat);
	fat = NULL;
	if ( block_write(sb.root_dir_index, root) == -1 ) { return -1; }
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
	if (block_disk_count() == -1 || !filename || filename[0] == '\0') {
		return -1;
	}
  	// if len is > 16, return -1
  	if ( strlen(filename) >= FS_FILENAME_LEN ) {
		return -1;
	}

	// @index: index of first free file
	int index = FS_FILE_MAX_COUNT;
  	for ( int i = 0; i < FS_FILE_MAX_COUNT; i++ ) {
		if ( strcmp(root[i].filename, filename) == 0 ) { //compare until '\0'
		 	return -1; //filename alrdy exists
		}
		if ( root[i].filename[0] == '\0' && i < index) {
			index = i;
		}
	}
	if ( index == FS_FILE_MAX_COUNT ) {
		return -1; //max_file in root alrdy
	}
	memset(root[index].filename, 0, FS_FILENAME_LEN);
    memcpy(root[index].filename, filename, strlen(filename));
	root[index].first_data_index = FAT_EOC;
	root[index].fileSize = 0; 
	//put into disk?--write root into disk
	if ( block_write(sb.root_dir_index, root) == -1 ) { 
		return -1; 
	} 
	return 0;
}

int fs_delete(const char *filename) {
	// check if disk count exists
	if ( block_disk_count() == -1 ) return -1;
	// invalid filename
	if ( !filename ) return -1;
	// if the file name is > 16, invalid filename
	if ( strlen(filename) >= FS_FILENAME_LEN ) return -1;

	//find file
	int found_index = -1;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (strcmp(root[i].filename, filename) == 0) {
			found_index = i;
			break;
		}
	}
	if (found_index == -1) return -1; //file not found
	//check if open
	for (int i = 0; i < FS_OPEN_MAX_COUNT; i++) {
		if (fd_table[i].on && fd_table[i].root_index == found_index) {
			return -1;//!what do we do if file is open and want to delete?
		}
	}
	//free data
	uint16_t cur_blk = root[found_index].first_data_index;
	while (cur_blk != FAT_EOC && cur_blk < sb.data_block_count) { //traverse ll
		uint16_t next_blk = fat[cur_blk];
		fat[cur_blk] = 0;
		cur_blk = next_blk;
	}
	//free root
	memset(&root[found_index], 0, sizeof(struct root_entry));
	root[found_index].first_data_index = FAT_EOC;
	//update disk
	if (block_write(sb.root_dir_index, root) == -1) return -1;
	for (int i = 0; i < sb.fat_block_count; i++) {
		if (block_write((1+i), (uint8_t*)fat+(i*BLOCK_SIZE)) == -1) return -1;
	}
	return 0;
}

int fs_ls(void) {
	if ( block_disk_count() == -1 ) return -1;

	printf("FS Ls:\n");
	for ( int i = 0; i < FS_FILE_MAX_COUNT; i++ ) {
		if ( root[i].filename[0] != '\0' ) {
			printf("file: %s, ", root[i].filename);
			printf("size: %u, ", root[i].fileSize);
			printf("data_blk: %u\n", root[i].first_data_index);
		}
	}
	return 0;
}

int fs_open(const char *filename) {
	if (block_disk_count() == -1) return -1; //not mounted
	if (!filename) return -1; //no filename
	if (strlen(filename) >= FS_FILENAME_LEN) return -1; //invalid filename-size
	//check for open fd
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (strcmp(root[i].filename, filename) != 0) continue;
		for (int j = 0; j < FS_OPEN_MAX_COUNT; j++) {
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
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) return -1; //invalid fd-out_bound
	if (!fd_table[fd].on) return -1; //invalid fd-not in use
	//close
	fd_table[fd].on = 0;
	fd_table[fd].file_offset = 0;
	return 0;
}

int fs_stat(int fd) {
	if (block_disk_count() == -1) return -1; //not mounted
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) return -1; //invalid fd-out_bound
	if (!fd_table[fd].on) return -1; //invalid fd-not in use
	//
	return root[fd_table[fd].root_index].fileSize;
}

int fs_lseek(int fd, size_t offset) {
	if (block_disk_count() == -1) return -1; //not mounted
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) return -1; //invalid fd-out_bound
	if (!fd_table[fd].on) return -1; //invalid fd-not in use
	size_t file_size = fs_stat(fd);
	if (offset > file_size) return -1; //offset > file_size
	//
	fd_table[fd].file_offset = offset;
	return 0;
}

static uint16_t get_block_index(int fd, size_t offset) {
	uint16_t start_index = root[fd_table[fd].root_index].first_data_index;
	size_t skipped_blocks = offset/BLOCK_SIZE;
	while (skipped_blocks > 0 && start_index != FAT_EOC) {
		start_index = fat[start_index];
		skipped_blocks--;
	}
	return start_index; 
}

static int get_free_fat() {
	for( int i = 0; i < sb.data_block_count; i++ ) {
		if ( fat[i] == 0 ) { return i; } 
	}
	return -1;
}

int fs_write(int fd, void *buf, size_t count) {
	if (block_disk_count() == -1) return -1; // not mounted
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) return -1; //invalid fd-out_bound
	if (!fd_table[fd].on) return -1; //invalid fd-not in use
	if (!buf) return -1; // buffer is empty
	if (count == 0) return 0; //nothing to do
	//
	size_t bytes_written = 0;
	uint8_t bounce_buf[BLOCK_SIZE];
	uint8_t *temp_buf = (uint8_t*)buf;
	size_t cur_offset = fd_table[fd].file_offset;
	//file empty--allocate first data_block
	if (root[fd_table[fd].root_index].first_data_index == FAT_EOC) {
		int first_free = get_free_fat();
		if (first_free == -1) return 0; // disk full
		root[fd_table[fd].root_index].first_data_index = first_free;
		fat[first_free] = FAT_EOC;
	}
	//
	while (bytes_written < count) {
		uint16_t cur_block = get_block_index(fd, cur_offset);
		//need new block
		if (cur_block == FAT_EOC) {
			int first_free = get_free_fat();
			if (first_free == -1) break; //disk full
			//
			uint16_t last_block = get_block_index(fd, cur_offset-1);
			if (last_block == FAT_EOC) break; //sanity check
			//
			fat[last_block] = first_free; //links the new block
			fat[first_free] = FAT_EOC; //makes tail NULL
			cur_block = first_free; //sets cur to block
		}
		//calc block offset
		size_t block_offset = cur_offset % BLOCK_SIZE;
		size_t bytes_write = BLOCK_SIZE - block_offset;
		if (bytes_write > count-bytes_written) bytes_write = count - bytes_written;
		//
		uint16_t cur_blk_idx = sb.data_start_index + cur_block;
		//read existing data
		if (block_offset != 0 || bytes_write != BLOCK_SIZE) {
			if (block_read(cur_blk_idx, bounce_buf) < 0) break;
		}
		//write data
		memcpy(bounce_buf+block_offset, temp_buf+bytes_written, bytes_write);
		if (block_write(cur_blk_idx, bounce_buf) < 0) break;
		//
		bytes_written += bytes_write;
		cur_offset += bytes_write;
	}
	//
	fs_lseek(fd, cur_offset);
	if ((int)cur_offset > fs_stat(fd)) {
		root[fd_table[fd].root_index].fileSize = cur_offset;
	}
	//write root && fat
	if (block_write(sb.root_dir_index, root) < 0) return -1;
	for (int i = 0; i < sb.fat_block_count; i++) {
		if (block_write(1+i, (uint8_t*)fat+(i*BLOCK_SIZE)) < 0) return -1;
	}
	return bytes_written;
}

int fs_read(int fd, void *buf, size_t count) {
	if (block_disk_count() == -1) return -1; //not mounted
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) return -1; //invalid fd-out_bound
	if (!fd_table[fd].on) return -1; //invalid fd-not in use
	if (!buf) return -1; //invalid buf
	if (count == 0) return 0; //nothing to read
	//
	size_t bytes_read = 0;
	size_t file_size = fs_stat(fd);
	uint8_t bounce_buf[BLOCK_SIZE];
	uint8_t *temp_buf = (uint8_t*)buf;
	size_t cur_offset = fd_table[fd].file_offset;
	if (cur_offset >= file_size) return 0; //nothing to read
	size_t to_read = (cur_offset+count > file_size) ? file_size - cur_offset : count;
	//
	while (bytes_read < to_read) {
		uint16_t cur_block = get_block_index(fd, cur_offset);
		if (cur_block == FAT_EOC) break;
		//partial block
		size_t block_offset = cur_offset % BLOCK_SIZE;
		size_t block_chunk = BLOCK_SIZE - block_offset;
		if (block_chunk > to_read-bytes_read) block_chunk = to_read - bytes_read;
		//read
		uint16_t cur_blk_idx = sb.data_start_index + cur_block;
		if (block_read(cur_blk_idx, bounce_buf) < 0) break;
		memcpy(temp_buf+bytes_read, bounce_buf+block_offset, block_chunk);
		//next block
		bytes_read += block_chunk;
		cur_offset += block_chunk;
	}
	fs_lseek(fd, cur_offset);
	return bytes_read;
}
