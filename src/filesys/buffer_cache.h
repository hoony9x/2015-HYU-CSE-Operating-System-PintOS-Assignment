#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H

#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/synch.h"

struct buffer_head
{
	bool dirty;
	bool valid;
	block_sector_t address;
	bool clock;
	struct lock lock;
	void *buffer;
};

bool bc_read(block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs);
bool bc_write(block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs);
void bc_init(void);
void bc_term(void);

struct buffer_head* bc_select_victim(void);
struct buffer_head* bc_lookup(block_sector_t sector);

void bc_flush_entry(struct buffer_head *p_flush_entry);
void bc_flush_all_entries(void);

#endif /* filesys/buffer_cache.h */