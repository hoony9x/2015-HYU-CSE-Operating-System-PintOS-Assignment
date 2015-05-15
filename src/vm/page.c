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

void vm_init(struct hash *vm)
{
	hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

void vm_destroy(struct hash *vm)
{
	hash_destroy(vm, vm_destroy_func);
}

static unsigned int vm_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *entry = hash_entry(e, struct vm_entry, elem);
	unsigned int hash_pos = hash_int((int)entry->vaddr);

	return hash_pos;
}

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
	struct vm_entry *entry_1 = hash_entry(a, struct vm_entry, elem);
	struct vm_entry *entry_2 = hash_entry(b, struct vm_entry, elem);

	if(entry_1->vaddr < entry_2->vaddr)
		return true;
	else
		return false;
}

static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *entry = hash_entry(e, struct vm_entry, elem);
	if(entry->is_loaded)
	{
		palloc_free_page(pagedir_get_page(thread_current()->pagedir, entry->vaddr));
		pagedir_clear_page(thread_current()->pagedir, entry->vaddr);
	}
	free(entry);
}

struct vm_entry* find_vme(void *vaddr)
{
	struct vm_entry *entry = (struct vm_entry*)malloc(sizeof(struct vm_entry));
	entry->vaddr = pg_round_down(vaddr);

	struct hash_elem *e = hash_find(&thread_current()->vm, &entry->elem);
	free(entry);

	if(e == NULL)
		return NULL;
	else
		return hash_entry(e, struct vm_entry, elem);
}

bool insert_vme(struct hash *vm, struct vm_entry *vme)
{
	if(hash_insert(vm, &vme->elem) == NULL)
		return true;
	else
		return false;
}

bool delete_vme(struct hash *vm, struct vm_entry *vme)
{
	hash_delete(vm, &vme->elem);

	return true;
}

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

void unpin_string(void *str)
{
	while(*(char*)str != '\0')
	{
		unpin_ptr(str);
		str = str + 1;
	}
}

void unpin_buffer(void *buffer, unsigned int size)
{
	unsigned int i;
	for(i = 0; i < size; i++)
	{
		unpin_ptr(buffer);
		buffer = buffer + 1;
	}
}

bool load_file(void *kaddr, struct vm_entry *vme)
{
	bool success = true;

	if(vme->read_bytes > 0)
	{
		lock_acquire(&filesys_lock);

		if(file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset) != (off_t)vme->read_bytes)
		{
			lock_release(&filesys_lock);
			success = false;
		}
		else
		{
			lock_release(&filesys_lock);
			memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
		}
	}
	else
		memset(kaddr, 0, PGSIZE);

	return success;
}