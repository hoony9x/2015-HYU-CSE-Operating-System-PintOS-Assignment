#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "threads/synch.h"
#include <stdbool.h>


#include <stdint.h>
#include <list.h>
#include "vm/page.h"

struct lock lru_list_lock;
struct list lru_list;
struct list_elem* lru_clock;

void lru_list_init(void);
void add_page_to_lru_list(struct page *page);
void del_page_from_lru_list(struct page *page);

struct page* alloc_page(enum palloc_flags flags);
void free_page(void *kaddr);
void __free_page(struct page *page);

struct list_elem* get_next_lru_clock(void);

void* try_to_free_pages(enum palloc_flags flags);

#endif /* vm/frame.h */