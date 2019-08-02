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

void
lru_list_init(void)
{
	/* Initialize LRU list */
	list_init(&lru_list);

	/* Initialize LRU list lock */
	lock_init(&lru_list_lock);

	/* Set inital value of lru_clock to NULL */
	lru_clock = NULL;
}

void
add_page_to_lru_list(struct page *page)
{
	/* Set lock for concurrency */
	lock_acquire(&lru_list_lock);

	/* Push page into end of LRU list */
	list_push_back(&lru_list, &page->lru);

	/* Release lock */
	lock_release(&lru_list_lock);
}

void
del_page_from_lru_list(struct page *page)
{
	/* Set lock for concurrency */
	//lock_acquire(&lru_list_lock);

	/* Remove page from LRU list */
	list_remove(&page->lru);

	/* Release lock */
	//lock_release(&lru_list_lock);
}

struct page*
alloc_page(enum palloc_flags flags)
{
	/* Get page address using palloc_get_page() */
	void *kaddr = palloc_get_page(flags);

	/* If failed to get page, use another function until kaddr has 'not NULL' address */
	/* Need use 'while' loop instead of 'if' condition */
	while(kaddr == NULL)
	{
		/* Set lock for concurrency */
		lock_acquire(&lru_list_lock);

		/* Try to get page address */
		kaddr = try_to_free_pages(flags);

		/* Release lock */
		lock_release(&lru_list_lock);
	}

	/* Set page and allocate memory for page */
	struct page *page = (struct page*)malloc(sizeof(struct page));

	/* Failed to allocate memory */
	if(page == NULL)
		return NULL;

	/* Set initial value of page */
	page->kaddr = kaddr;
	page->thread = thread_current();
	page->vme = NULL;

	/* Add this page into LRU list */
	add_page_to_lru_list(page);

	return page;
}

/* Search page subject to free */
void
free_page(void *kaddr)
{
	struct list_elem *e; /* Will temporary store each object in child list. */
	for(e = list_begin(&lru_list); e != list_end(&lru_list);)
	{
		/* Temporary store next_elem */
		struct list_elem *next_elem = list_next(e);

		/* Get page from LRU list */
		struct page *page = list_entry(e, struct page, lru);

		/* If find target kaddr, free this page and break */
		if(page->kaddr == kaddr)
		{
			__free_page(page);
			break;
		}

		/* Set next_elem */
		e = next_elem;
	}
}

/* Actually doing free task */
void
__free_page(struct page *page)
{
	/* Set lock for concurrency */
	lock_acquire(&lru_list_lock);

	/* First, remove target page from LRU list */
	del_page_from_lru_list(page);

	/* Release lock */
	lock_release(&lru_list_lock);

	/* Second, free target address */
	palloc_free_page(page->kaddr);

	/* Finally, deallocate memory allocated to this page */
	free(page);
}

struct list_elem*
get_next_lru_clock(void)
{
	/* If lru_clock is NULL value, return NULL */
	if(lru_clock == NULL)
		return NULL;

	/* If size of LRU list is 1, return NULL */
	if(list_size(&lru_list) == 1)
		return NULL;

	/* Get next element */
	struct list_elem *next_elem = list_next(lru_clock);

	/* If current element is end of list, set to begin point */
	if(next_elem == list_end(&lru_list))
		next_elem = list_begin(&lru_list);

	return next_elem;
}

/* To check success or fail, set return type as void pointer */
void*
try_to_free_pages(enum palloc_flags flags)
{
	if(list_empty(&lru_list) == true)
	{
		lru_clock = NULL;
		return NULL;
	}

	/* If lru_clock did not points LRU list, set initial value. */
	if(lru_clock == NULL)
		lru_clock = list_begin(&lru_list);

	/* Do again and again until it get free space */
	while(lru_clock)
	{
		/* Get next element of LRU list selected by LRU clock algorithm */
		struct list_elem *next = get_next_lru_clock();

		/* Get page pointed by 'next' */
		struct page *page = list_entry(lru_clock, struct page, lru);

		/* Set lru_clock to next value. */
		lru_clock = next;

		/* In this task, it will check if this is pinned or not. If pinned, it is not subject to free. */
		/* So, if pinned value is false, it is subject to free. */
		if(!page->vme->pinned)
		{
			/* Get thread info correspond to target page. */
			struct thread *t = page->thread;

			if(pagedir_is_accessed(t->pagedir, page->vme->vaddr))
			{
				/* If accessed bit is 1, set 0 and find another page. */
				pagedir_set_accessed(t->pagedir, page->vme->vaddr, false);
			}
			else
			{
				/* If dirty-bit is 1 or VM's type is VM_ANON, flush to disk. */
				/* Else, it doesn't need to be flushed to disk. */
				if(pagedir_is_dirty(t->pagedir, page->vme->vaddr) || page->vme->type == VM_ANON)
				{
					if(page->vme->type == VM_FILE)
					{
						/* If VM type is VM_FILE, flush to disk. */
						/* Maybe this is memory-mapped file. */

						/* Set lock for concurrency */
						lock_acquire(&filesys_lock);

						/* Transfer data from memory to disk. */
						file_write_at(page->vme->file, page->kaddr, page->vme->read_bytes, page->vme->offset);

						/* Release lock */
						lock_release(&filesys_lock);
					}
					else if(page->vme->type != VM_ERROR)
					{
						/* Set VM type as VM_ANON. This will be flushed to Swap space. */
						page->vme->type = VM_ANON;

						/* Swap out and set swap_slot. */
						page->vme->swap_slot = swap_out(page->kaddr);
					}
				}

				/* Set 'is_loaded' false as it will be removed from memory. */
				page->vme->is_loaded = false;

				/* Delete this page from LRU list. */
	            del_page_from_lru_list(page);

	            /* Deallocate memory allocated for page. */
	            pagedir_clear_page(t->pagedir, page->vme->vaddr);
	            palloc_free_page(page->kaddr);
	            free(page);

				/* Get new page for request and return address. */
	            return palloc_get_page(flags);
			}
		}
	}

	return NULL;
}