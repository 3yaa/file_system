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
	fat = calloc((size_t)sb.data_block_count, BLOCK_SIZE);
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
		if ( memcmp(root[i].filename, filename, strlen(filename) ) == 0 ) {
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
	if ( block_write(sb.root_dir_index, &root) == -1 ) { 
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

	for ( int i = 0; i < FS_FILE_MAX_COUNT; i++ ) {
		if ( memcmp(root[i].filename, filename, strlen(filename)) == 0)  {
			root[i].filename[0] = '\0'; 
			root[i].fileSize = 0;
			root[i].first_data_index = FAT_EOC; 
			if ( block_write(sb.root_dir_index, &root) == -1 ) { return -1; } // might be wrong lol
			return 0;
		}
	}
	return -1;
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
	for (size_t i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (memcmp(root[i].filename, filename, strlen(filename)) != 0) continue;
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

static size_t start_block_index(int fd, size_t offset) {
	size_t start_index = root[fd_table[fd].root_index].first_data_index;
	size_t skipped_blocks = offset/BLOCK_SIZE;
	while (skipped_blocks && start_index != FAT_EOC) {
		start_index = fat[start_index];
		skipped_blocks--;
	}
	return start_index; 
}

int get_FAT() {
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
	//
	size_t start = fd_table[fd].file_offset;
	if ( root[fd_table[fd].root_index].first_data_index == FAT_EOC ) { root[fd].first_data_index = get_FAT(); }
	
	// if (root[fd_table[fd].root_index].first_data_index == FAT_EOC) {
	// 	int first_free = get_FAT();
	// 	if (first_free == -1) return -1; // disk full
	// 	root[fd_table[fd].root_index].first_data_index = first_free;
	// 	fat[first_free] = FAT_EOC;
	// }

	size_t block_index = sb.data_start_index + start_block_index(fd, start);
	size_t start_byte = start % BLOCK_SIZE;
	uint8_t bounce_buf[BLOCK_SIZE];
	uint8_t *temp_buf = buf;
	size_t write_left = count;
	
	while (write_left > 0) {

		//section: start-x
		if (start_byte) {
			if (block_read(block_index, bounce_buf) < 0) {	
				return -1;
			}
			size_t blk_size = BLOCK_SIZE-start_byte; 
			memcpy(bounce_buf, temp_buf, blk_size);
			if (block_write(block_index, bounce_buf) < 0) {
				return -1;
			}
			//
			start_byte = 0;
			temp_buf += blk_size;
			write_left -= blk_size;
			start += blk_size; // add the blk_size to the current offset to update it
			fs_lseek(fd, start+start_byte);
			//
			if (write_left) {
				if (fat[block_index] == FAT_EOC) {
					//make new data block
					int first_free = get_FAT();
					if ( first_free == -1 ) { // no FAT open, disk full
						 if ( block_write(sb.root_dir_index, &root) == -1 ) { return -1; } // might be wrong lol
						return count - write_left;
					} else {
						fat[block_index] = first_free;
						fat[first_free] = FAT_EOC;
						block_index = sb.data_start_index + first_free;
						root[fd_table[fd].root_index].fileSize += BLOCK_SIZE;
					}
				} else {
					block_index = fat[block_index];	
				}	
			}
		}
		
		//section: full blocks
		if (write_left >= BLOCK_SIZE) {
			if (fat[block_index] == FAT_EOC) {
				//make new data block
				int first_free = get_FAT();
				if ( first_free == -1 ) { // no FAT open, disk full
					if ( block_write(sb.root_dir_index, &root) == -1 ) { return -1; } // might be wrong lol
					return count - write_left;
				} else {
					fat[block_index] = first_free;
					fat[first_free] = FAT_EOC;
					block_index = sb.data_start_index + first_free;
					root[fd_table[fd].root_index].fileSize += BLOCK_SIZE;
				}
			} else {
				block_index = fat[block_index];
			}

			if (block_write(block_index, bounce_buf) < 0) {
				return -1;
			}
			//
			temp_buf += BLOCK_SIZE;
			write_left -= BLOCK_SIZE;
			fs_lseek(fd, fd_table[fd].file_offset+BLOCK_SIZE);
			//
			if (write_left) {
				if (fat[block_index] == FAT_EOC) {
					//make new data block
					int first_free = get_FAT();
					if ( first_free == -1 ) { // no FAT open, disk full
						if ( block_write(sb.root_dir_index, &root) == -1 ) { return -1; } // might be wrong lol
						return count - write_left; // actual number of bytes written
					} else {
						fat[block_index] = first_free;
						fat[first_free] = FAT_EOC;
						block_index = sb.data_start_index + first_free;
						root[fd_table[fd].root_index].fileSize += BLOCK_SIZE;
					}
				} else {
					block_index = fat[block_index];
				}
			}
			continue;
		}

		//printf("blk_idx: %ld\n", block_index);
		//printf("fat[blk_idx]: %d\n", fat[block_index]);

		//section: x-end
		if (block_index - sb.data_start_index == FAT_EOC) {
			//printf("hn\n");
			//make new data block
			int first_free = get_FAT();
			if ( first_free == -1 ) { // no FAT open, disk full
				if ( block_write(sb.root_dir_index, &root) == -1 ) { return -1; } // might be wrong lol
				return count - write_left;
			} else {
				block_index = first_free + sb.data_start_index;
				fat[first_free] = FAT_EOC;
				root[fd_table[fd].root_index].fileSize += BLOCK_SIZE;
			}
		} else {
			//printf("here???\n");
			root[fd_table[fd].root_index].fileSize += write_left;
			//block_index = fat[block_index];
			//block_index = sb.data_start_index + block_index;
			// root[fd_table[fd].root_index].fileSize += write_left;
		}
		//printf("writing to block_index: %ld\n", block_index);
		if (block_write(block_index, temp_buf) < 0) {
			return -1;
		}
		fs_lseek(fd, fd_table[fd].file_offset+write_left);
		write_left = 0;
	}
	if (fd_table[fd].file_offset > root[fd_table[fd].root_index].fileSize) {
		root[fd_table[fd].root_index].fileSize = fd_table[fd].file_offset;
	} 
	if ( block_write(sb.root_dir_index, &root) == -1 ) { return -1; } // might be wrong lol

	
	//printf("file size: %d\n", root[fd_table[fd].root_index].fileSize);
	//printf("offset: %d\n", fd_table[fd].file_offset);
	return count;
}

int fs_read(int fd, void *buf, size_t count) {
	if (block_disk_count() == -1) return -1; //not mounted
	if (fd < 0 || fd >= FS_OPEN_MAX_COUNT) return -1; //invalid fd-out_bound
	if (!fd_table[fd].on) return -1; //invalid fd-not in use
	if (!buf) return -1; //invalid buf
	//
	size_t start = fd_table[fd].file_offset;
	//printf("start is %ld\n", start);
	size_t file_size = fs_stat(fd);
	if (start >= file_size) return 0; //nothing to read
	size_t to_read = (start+count > file_size) ? file_size - start : count;
	//
	size_t block_index = sb.data_start_index + start_block_index(fd, start);
	if ( block_index > FAT_EOC ) { block_index -= FAT_EOC; }
	//printf("block index for read is %ld\n", block_index);
	//printf("start block index is %d\n", sb.data_start_index);
	size_t start_byte = start % BLOCK_SIZE; //where to start in block
	uint8_t bounce_buf[BLOCK_SIZE];
	uint8_t *temp_buf = buf;
	size_t read_left = to_read;
	while (read_left > 0) {
		if (block_read(block_index, bounce_buf) < 0) return -1;
		size_t block_chunk = BLOCK_SIZE - start_byte;
		if (block_chunk > read_left) block_chunk = read_left;
		memcpy(temp_buf, bounce_buf+start_byte, block_chunk);
		//next block
		start_byte = 0; //after first no longer needs
		read_left -= block_chunk;
		temp_buf += block_chunk;
		if (read_left) {
			block_index = fat[block_index];
			if (block_index == FAT_EOC) break;
			block_index = sb.data_start_index + block_index;
		}
	}
	size_t actual_read = to_read-read_left;
	fs_lseek(fd, actual_read); //!might need to double check
	return (int)actual_read;
}
