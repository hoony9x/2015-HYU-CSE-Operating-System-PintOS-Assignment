#include "filesys/buffer_cache.h"
#include "threads/palloc.h"
#include <string.h>
#include "threads/malloc.h"
#include <debug.h>

#define BUFFER_CACHE_ENTRIE_NB 64

struct buffer_head *buffer_head;
char *p_buffer_cache;
struct buffer_head *clock_hand;

struct lock bc_lock;

bool
bc_read(block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs)
{
	/* Search sector_idx in buffer_head using bc_lookup() function. */
	struct buffer_head *head = bc_lookup(sector_idx);

	/* If failed to search.. */
	if(!head)
	{
		/* Use LRU algorithm to select victim. */
		head = bc_select_victim();

		/* Transfer data from buffer cache to disk. (Prepare for new data) */
		bc_flush_entry(head);

		/* Set cache block's value */
		head->valid = true;
		head->dirty = false;
		head->address = sector_idx;

		lock_release (&bc_lock);
		block_read(fs_device, sector_idx, head->buffer);
	}

	/* Set clock value. */
	head->clock = true;

	/* Copy data from disk to buffer cache. */
	memcpy(buffer + bytes_read, head->buffer + sector_ofs, chunk_size);

	lock_release(&head->lock);

	return true;
}

bool
bc_write(block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs)
{
	bool success = false;

	/* Search sector_idx in buffer_head using bc_lookup() function. */
	struct buffer_head *head = bc_lookup(sector_idx);

	/* If failed to search.. */
	if(!head)
	{
		/* Use LRU algorithm to select victim. */
		head = bc_select_victim ();

		/* Transfer data from buffer cache to disk. (Prepare for new data) */
		bc_flush_entry (head);

		/* Set cache block's value */
		head->valid = true;
		head->address = sector_idx;

		lock_release(&bc_lock);
		block_read(fs_device, sector_idx, head->buffer);
	}

	/* Set clock value and dirty value. */
	head->clock = true;
	head->dirty = true;

	/* Copy data from disk to buffer cache. */
	memcpy(head->buffer + sector_ofs, buffer + bytes_written, chunk_size);

	lock_release(&head->lock);
	success = true;

	return success;
}

void
bc_init(void)
{
	/* Initialize buffer_head */
	buffer_head = (struct buffer_head*)malloc(sizeof(struct buffer_head) * BUFFER_CACHE_ENTRIE_NB);
	memset(buffer_head, 0, sizeof(struct buffer_head) * BUFFER_CACHE_ENTRIE_NB);

	/* Allocate buffer cache in memory. */
	p_buffer_cache = (char*)malloc(sizeof(char) * (BUFFER_CACHE_ENTRIE_NB * BLOCK_SECTOR_SIZE));
	memset(p_buffer_cache, 0, sizeof(char) * (BUFFER_CACHE_ENTRIE_NB * BLOCK_SECTOR_SIZE));

	struct buffer_head *head;
	void *cache = p_buffer_cache;

	for(head = buffer_head; head != buffer_head + BUFFER_CACHE_ENTRIE_NB;)
	{
		/* Initialize each head block */
		memset(head, 0, sizeof (struct buffer_head));
		lock_init (&head->lock);
		head->buffer = cache;

		head++;
		cache += BLOCK_SECTOR_SIZE;
	}

	/* Set clock_hand as buffer_head's first block */
	clock_hand = buffer_head;

	lock_init (&bc_lock);
}

void
bc_term(void)
{
	/* Flush all buffer_cache entries. */
	bc_flush_all_entries();

	/* Deallocate memory */
	free(p_buffer_cache);
	free(buffer_head);
}

struct buffer_head*
bc_select_victim(void)
{
	bool escapecheck = false;
	struct buffer_head *return_result = NULL;

	/* Infinite loop until it finds victim */
	while(!escapecheck)
	{
		/* Iterate each entry and get victim using approximated LRU algorithm. */
		for(; clock_hand != buffer_head + BUFFER_CACHE_ENTRIE_NB; clock_hand++)
		{
			lock_acquire (&clock_hand->lock);

			if(!clock_hand->valid || !clock_hand->clock)
			{
				return_result = clock_hand;
				clock_hand++;

				escapecheck = true;
				break;
			}

			clock_hand->clock = false;
			lock_release (&clock_hand->lock);
		}

		clock_hand = buffer_head;
	}

	return return_result;
}

struct buffer_head*
bc_lookup(block_sector_t sector)
{
	lock_acquire (&bc_lock);
	struct buffer_head *head;

	/* Iterate each entry and matching sector value. If find, return correpond value. Else, return NULL. */
	for(head = buffer_head; head != buffer_head + BUFFER_CACHE_ENTRIE_NB; head++)
	{
		if(head->valid && head->address == sector)
		{
			lock_acquire(&head->lock);
			lock_release(&bc_lock);

			return head;
		}
	}

	return NULL;
}

void
bc_flush_entry(struct buffer_head *p_flush_entry)
{
	if(!p_flush_entry->valid || !p_flush_entry->dirty)
		return;

	/* Set dirty value as false */
	p_flush_entry->dirty = false;

	/* Transfer data from memory to disk. */
	block_write(fs_device, p_flush_entry->address, p_flush_entry->buffer);
}

void
bc_flush_all_entries(void)
{
	struct buffer_head *head;

	/* Flush all data from memory to disk. */
	for(head = buffer_head; head != buffer_head + BUFFER_CACHE_ENTRIE_NB; head++)
	{
		lock_acquire(&head->lock);
		bc_flush_entry(head);
		lock_release(&head->lock);
	}
}