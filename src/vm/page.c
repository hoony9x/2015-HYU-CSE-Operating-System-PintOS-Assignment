#include <string.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

#include "vm/page.h"

static unsigned int vm_hash_func(const struct hash_elem *e, void *aux UNUSED);
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED);

/* Initialize hash table for VM */
void vm_init(struct hash *vm)
{
	hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

/* Destroy hash table for VM */
void vm_destroy(struct hash *vm)
{
	hash_destroy(vm, vm_destroy_func);
}

/* Generate hash position for VM hash table, and position will be generated from vaddr */
static unsigned int vm_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *entry = hash_entry(e, struct vm_entry, elem);
	unsigned int hash_pos = hash_int((int)entry->vaddr);

	return hash_pos;
}

/* This is compare function for hash_init function */
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
	struct vm_entry *entry_1 = hash_entry(a, struct vm_entry, elem);
	struct vm_entry *entry_2 = hash_entry(b, struct vm_entry, elem);

	if(entry_1->vaddr < entry_2->vaddr)
		return true;
	else
		return false;
}

/* This function will be used for hasy_destory() function */
static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *entry = hash_entry(e, struct vm_entry, elem);
	if(entry->is_loaded)
	{
		/* Clear page allocated for VM entry */
		palloc_free_page(pagedir_get_page(thread_current()->pagedir, entry->vaddr));
		pagedir_clear_page(thread_current()->pagedir, entry->vaddr);
	}
	free(entry);
}

/* Get VM entry from vaddr */
struct vm_entry* find_vme(void *vaddr)
{
	struct vm_entry *entry = (struct vm_entry*)malloc(sizeof(struct vm_entry));
	entry->vaddr = pg_round_down(vaddr);
	/* Get VM entry and set page */

	struct hash_elem *e = hash_find(&thread_current()->vm, &entry->elem);
	free(entry);
	/* Find target element from VM hash table. */

	if(e == NULL)
		return NULL;
	else
		return hash_entry(e, struct vm_entry, elem);
}

/* Insert VM entry into VM hash table */
bool insert_vme(struct hash *vm, struct vm_entry *vme)
{
	if(hash_insert(vm, &vme->elem) == NULL)
		return true;
	else
		return false;
}

/* Delete VM entry from VM hash table */
bool delete_vme(struct hash *vm, struct vm_entry *vme)
{
	hash_delete(vm, &vme->elem);

	return true;
}

/* Set pin value in VM entry false. */
bool unpin_ptr(void *vaddr)
{
	struct vm_entry *entry = find_vme(vaddr);
	
	if (entry)
	{
		entry->pinned = false;
		return true;
	}
	else
		return false;
}

/* Set all pin value false in VM entry related to string's each address. */
void unpin_string(void *str)
{
	while(*(char*)str != '\0')
	{
		unpin_ptr(str);
		str = str + 1;
	}
}

/* Set all pin value false in VM entry related to buffer and size */
void unpin_buffer(void *buffer, unsigned int size)
{
	unsigned int i;
	for(i = 0; i < size; i++)
	{
		unpin_ptr(buffer);
		buffer = buffer + 1;
	}
}

/* Used in handle_mm_fault() function. This will set page table. Read data from stored file and copy into kaddr(page size allocated). */
bool load_file(void *kaddr, struct vm_entry *vme)
{
	bool success = true;

	if(vme->read_bytes > 0) /* If there are some data to be read */
	{
		lock_acquire(&filesys_lock);

		/* If file_read size isn't equal to expected read_bytes, fail */
		if(file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset) != (off_t)vme->read_bytes)
		{
			lock_release(&filesys_lock);
			success = false;
		}
		else
		{
			lock_release(&filesys_lock);

			/* Set remain space with zero fill. */
			memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
		}
	}
	else /* If there is no data to be read, just set page zero filled with PGSIZE. */
		memset(kaddr, 0, PGSIZE);

	return success;
}