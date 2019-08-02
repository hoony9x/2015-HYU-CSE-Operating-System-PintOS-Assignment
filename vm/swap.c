#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

struct lock swap_lock;
struct block *swap_block;
struct bitmap *swap_map;

void
swap_init(void)
{
	/* Initialize swap block */
	swap_block = block_get_role(BLOCK_SWAP);

	/* Failed to initialize */
	if(swap_block == NULL)
		return;

	/* Initialize swap bitmap */
	swap_map = bitmap_create(block_size(swap_block) / SECTORS_PER_PAGE);

	/* Failed to initialize */
	if(swap_map == NULL)
		return;

	/* Set all bitmap to free. This can make all swap slot available. */
	bitmap_set_all(swap_map, SWAP_FREE);

	/* Initialize swap_lock */
	lock_init(&swap_lock);
}

void
swap_in(size_t used_index, void *kaddr)
{
	/* In this case, Swap space is not intialized or not available */
	if(swap_block == NULL || swap_map == NULL)
	{
		/* Nothing we can do. Just return. */

		return;
	}

	/* Set lock for concurrency */
	lock_acquire(&swap_lock);

	/* Check if target space of index is free or not. */
	if(bitmap_test(swap_map, used_index) == SWAP_FREE)
	{
		/* In swap_in(), data will be transfered from Disk to Memory. */
		/* But target Swap space indexed is free space. */
		/* Shoud not reach here! */

		PANIC("Trying to use free swap space!");
	}
	else
	{
		/* Transfer data from Disk to Memory */
		unsigned int i;
		for(i = 0; i < SECTORS_PER_PAGE; i++)
			block_read(swap_block, used_index * SECTORS_PER_PAGE + i, (uint8_t*) kaddr + i * BLOCK_SECTOR_SIZE);

		/* Reverse bit-set state. If 0, set 1. Else if 1, set 0. */
		bitmap_flip(swap_map, used_index);
	}

	/* Release lock */
	lock_release(&swap_lock);
}

size_t
swap_out(void *kaddr)
{
	/* In this case, Swap space is not intialized or not available */
	if(swap_block == NULL || swap_map == NULL)
	{
		/* This function trying to swap out task. */
		/* So, available Swap space needed but nothing. */
		/* Shoud not reach here! */

		PANIC("Swap space is not initialized or not available!");
	}

	/* Set lock for concurrency */
	lock_acquire(&swap_lock);
	
	/* Find the first index of available bits. Then, set bit-state as SWAP_FREE. */
	size_t free_index = bitmap_scan_and_flip(swap_map, 0, 1, SWAP_FREE);

	/* If index equals to max size, it means that no available space is in swap. */
	if(free_index == BITMAP_ERROR)
	{
		/* This function trying to swap out task. */
		/* So, we need free space but in this case, no available space! */
		/* Shoud not reach here! */

		PANIC("No available space is in swap space!");
	}
	else
	{
		/* Transfer data from Memory to Disk */
		unsigned int i;
		for(i = 0; i < SECTORS_PER_PAGE; i++)
		{
			block_write(swap_block, free_index * SECTORS_PER_PAGE + i, (uint8_t *) kaddr+ i * BLOCK_SECTOR_SIZE);
		}
	}

	/* Release lock */
	lock_release(&swap_lock);

	return free_index;
}