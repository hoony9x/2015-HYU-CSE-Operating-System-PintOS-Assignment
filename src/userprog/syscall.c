#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <devices/shutdown.h> /* Added to use 'shutdown_power_off' function */
#include <filesys/filesys.h> /* Added to use filesystem related function */
#include <filesys/file.h> /* Added to use filesystem related function */
#include <devices/input.h> /* Added to use input_getc() function */
#include "userprog/process.h" /* Added to use process_execute() */
#include "threads/synch.h" /* Added to use lock */
#include "vm/page.h" /* Added to use VM */
#include "threads/vaddr.h" /* Added to use VM */
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

/* This file structure will be used for file descriptor table. Copied from file.c */
struct file 
{
	struct inode *inode;        /* File's inode. */
	off_t pos;                  /* Current position. */
	bool deny_write;            /* Has file_deny_write() been called? */
};

struct vm_entry* check_address(void *addr, void *esp UNUSED);
void get_argument(unsigned int *esp, unsigned int *arg[5], int count);

int mmap(int fd, void *addr);
void munmap(int mapping);
void do_munmap(struct mmap_file *mmap_f);

void sys_halt(void);
void sys_exit(int status);
bool sys_create(const char *file, unsigned int initial_size);
bool sys_remove(const char *file);
tid_t sys_exec(char *exec_filename);
int sys_wait(tid_t tid);
int sys_open(const char *open_filename);
int sys_filesize(int fd);
int sys_read(int fd, char *buffer, unsigned int size);
int sys_write(int fd, char *buffer, unsigned int size);
void sys_seek(int fd, unsigned int position);
unsigned int sys_tell(int fd);
void sys_close(int fd);

void
syscall_init (void) 
{
	lock_init(&filesys_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  	unsigned int *esp = (unsigned int*)(f->esp); //Stack pointer from interrupt frame
	if(check_address(esp, esp) == NULL)
		sys_exit(-1);

	unsigned int *argument[5]; //Arguments for system call will be stored temporary.
	int system_call_number = *(int*)esp; //Recognize system call number. This will be used for switch case block.

	esp = esp + 1; //Increase stack pointer value.
	
	/* Check again */
	if(check_address(esp, esp) == NULL)
		sys_exit(-1);

	switch(system_call_number)
	{
		case SYS_HALT:
			sys_halt();
			break;

		case SYS_EXIT:
			{
				get_argument(esp, argument, 1); //One argument will be used.

				/* Argument type casting section. */
				int exit_status = (int)*(argument[0]); //Type casting.

				sys_exit(exit_status);
			}
			break;

		case SYS_EXEC:
			{
				get_argument(esp, argument, 1); //One argument will be used.

				/* Argument type casting section. */
				char *exec_filename = (char*)*(argument[0]); //Type casting.

				/* Check validity */
				check_valid_string(exec_filename, esp);

				f->eax = sys_exec(exec_filename); //Store return value to eax.
				unpin_string(exec_filename);
			}
			break;
			
		case SYS_WAIT:
			{
				get_argument(esp, argument, 1); //One argument will be used.

				/* Argument type casting section. */
				int wait_tid = (int)*(argument[0]); //Type casting.

				f->eax = sys_wait(wait_tid); //Store return value to eax.
			}
			break;

		case SYS_CREATE:
			{
				get_argument(esp, argument, 2); //Two arguments will be used.

				/* Argument type casting section. */
				char *create_filename = (char*)*(argument[0]);
				unsigned int initial_size = (int)*(argument[1]);

				/* Check validity */
				check_valid_string(create_filename, esp);

				f->eax = sys_create(create_filename, initial_size); //Store return value to eax.
				unpin_string(create_filename);
			}
			break;
			
		case SYS_REMOVE:
			{
				get_argument(esp, argument, 1); //One argument will be used.

				/* Argument type casting section. */
				char *remove_filename = (char*)*(argument[0]); //Type casting.

				/* Check validity */
				check_valid_string(remove_filename, esp);

				f->eax = sys_remove(remove_filename); //Store return value to eax.
				unpin_string(remove_filename);
			}
			break;

		case SYS_OPEN:
			{
				get_argument(esp, argument, 1); //One argument will be used.

				/* Argument type casting section. */
				char *open_filename = (char*)*(argument[0]);

				/* Check validity */
				check_valid_string(open_filename, esp);

				f->eax = sys_open(open_filename); //Store return value to eax.
				unpin_string(open_filename);
			}
			break;
			
		case SYS_FILESIZE:
			{
				get_argument(esp, argument, 1); //One argument will be used.

				/* Argument type casting section. */
				int fd = (int)*(argument[0]);

				f->eax = sys_filesize(fd); //Store return value to eax.
			}
			break;

		case SYS_READ:
			{
				get_argument(esp, argument, 3); //Three arguments will be used.

				/* Argument type casting section. */
				int fd = (int)*(argument[0]);
				char *buffer = (char*)*(argument[1]);
				unsigned int size = (unsigned int)*(argument[2]);

				/* Check validity */
				check_valid_buffer(buffer, size, esp, true);

				f->eax = sys_read(fd, buffer, size); //Store return value to eax.
				unpin_buffer(buffer, size);
			}
			break;

		case SYS_WRITE:
			{
				get_argument(esp, argument, 3); //Three arguments will be used.

				/* Argument type casting section. */
				int fd = (int)*(argument[0]);
				char *buffer = (char*)*(argument[1]);
				unsigned int size = (unsigned int)*(argument[2]);

				/* Check validity */
				check_valid_buffer(buffer, size, esp, false);

				f->eax = sys_write(fd, buffer, size); //Store return value to eax.
				unpin_buffer(buffer, size);
			}
			break;

		case SYS_SEEK:
			{
				get_argument(esp, argument, 2); //Two arguments will be used.

				/* Argument type casting section. */
				int fd = (int)*(argument[0]);
				unsigned int position = (unsigned int)*(argument[1]);

				sys_seek(fd, position); //Store return value to eax.
			}
			break;
			
		case SYS_TELL:
			{
				get_argument(esp, argument, 1); //Three arguments will be used.

				/* Argument type casting section. */
				int fd = (int)*(argument[0]);

				f->eax = sys_tell(fd); //Store return value to eax.
			}
			break;
			
		case SYS_CLOSE:
			{
				get_argument(esp, argument, 1); //Three arguments will be used.

				/* Argument type casting section. */
				int fd = (int)*(argument[0]);

				sys_close(fd); //Store return value to eax.
			}
			break;

		case SYS_MMAP:
			{
				get_argument(esp, argument, 2); //Two arguments will be used.

				/* Argument type casting section. */
				int fd = (int)*(argument[0]);
				char *buffer = (char*)*(argument[1]);

				f->eax = mmap(fd, buffer); //Store return value to eax.
			}
			break;

		case SYS_MUNMAP:
			{
				get_argument(esp, argument, 1); //One argument will be used.

				/* Argument type casting section. */
				int mapping = (int)*(argument[0]);

				munmap(mapping);
			}
			break;
			
		default:
			NOT_REACHED (); //If handler is correctly implemented, this line should not be executed.
			break;
	}

	unpin_ptr(esp);
}

/* Check address if it is valid address */
struct vm_entry*
check_address(void *addr, void *esp UNUSED)
{
	/* Check address and if address value is out of range, exit process. */
	if((unsigned int)addr <= (unsigned int)USER_ADDR_LOW_BOUNDARY || (unsigned int)addr >= (unsigned int)USER_ADDR_MAX_BOUNDARY)
		sys_exit(-1);

	/* Get VM entry */
	struct vm_entry *entry = find_vme(addr);
	if(entry)
	{
		/* Set entry's pin value to true. */
		entry->pinned = true;

		/* handle_mm_fault() if entry is not loaded. */
		handle_mm_fault(entry);
	}

	/* If failed to load, exit(-1) */
	if(entry != NULL && entry->is_loaded == false)
		sys_exit(-1);

	return entry;
}

/* Check buffer's address validity */
void
check_valid_buffer(void *buffer, unsigned int size, void *esp, bool to_write)
{
	void *ptr = (void*)buffer;
	unsigned int i;
	struct vm_entry *entry;

	for(i = 0; i < size; i++)
	{
		entry = check_address(ptr, esp);
		if(entry == NULL)
			sys_exit(-1);

		if(entry != NULL && (to_write == true && entry->writable == false))
		{
			sys_exit(-1);
		}

		ptr = ptr + 1;
	}
}

/* Check string's address validity */
void
check_valid_string(const void *str, void *esp)
{
	void *ptr = (void*)str;
	struct vm_entry *entry;

	entry = check_address(ptr, esp);
	if(entry == NULL)
		sys_exit(-1);

	while(*(char*)ptr != '\0')
	{
		entry = check_address(ptr, esp);

		if(entry == NULL)
			sys_exit(-1);

		ptr = ptr + 1;
	}

	entry = check_address(ptr, esp);
	if(entry == NULL)
		sys_exit(-1);
}

/* Get argument from esp and store them into kernel stack */
void
get_argument(unsigned int *esp, unsigned int *arg[5], int count)
{
	int i;
	for(i = 0; i < count; i++)
	{
		/* Before store arguments from esp to kernel stack, check every esp pointer value. */
		check_address((void*)esp, (void*)esp);
		arg[i] = esp; /* Insert each esp address into kernel stack */
		esp++;
	}
}

/* Do a file memory mapping */
int
mmap(int fd, void *addr)
{
	/* Get file info */
	struct file *fp = process_get_file(fd);
	if(fp == NULL)
		return -1;

	/* check address and wordaligned state. */
	if((unsigned int)addr <= (unsigned int)USER_ADDR_LOW_BOUNDARY ||
		(unsigned int)addr >= (unsigned int)USER_ADDR_MAX_BOUNDARY ||
		(unsigned int)addr % PGSIZE != 0)
		return -1;

	/* Reopen file and get length info */
	struct file *fp_reopen = file_reopen(fp);
	int file_len = file_length(fp_reopen);

	/* Check reopend state and file length */
	if(fp_reopen == NULL || file_len == 0)
		return -1;

	/* Set mapid, and increase mapid count. */
	int mapid = thread_current()->mapid;
	thread_current()->mapid++;

	/* Allocate and set mapid for mmap_file structure */
	struct mmap_file *mmap_f = (struct mmap_file*)malloc(sizeof(struct mmap_file));
	list_init(&mmap_f->vme_list);
	mmap_f->file = fp_reopen;
	mmap_f->mapid = mapid;

	int offset = 0;

	while(file_len > 0)
	{
		/* Set read_bytes and zero_bytes */
		unsigned int read_bytes = file_len;
		if(file_len > PGSIZE)
			read_bytes = PGSIZE;
		unsigned int zero_bytes = PGSIZE - read_bytes;

		if(find_vme(addr) != NULL)
		{
			munmap(mapid);
			return -1;
		}

		/* Allocate memory for vm_entry. */
		struct vm_entry *entry = (struct vm_entry*)malloc(sizeof(struct vm_entry));
		if(entry == NULL)
		{
			munmap(mapid);
			return -1;
		}

		/* Initialize entry */
		entry->file = fp_reopen;
		entry->offset = offset;
		entry->vaddr = addr;
		entry->read_bytes = read_bytes;
		entry->zero_bytes = zero_bytes;
		entry->type = VM_FILE;
		entry->writable = true;			
		entry->pinned = false;
		entry->is_loaded = false;

		/* Insert entry into vme_list */
		list_push_back(&mmap_f->vme_list, &entry->mmap_elem);
		insert_vme(&thread_current()->vm, entry);

		/* Calculating changes */
		file_len -= read_bytes;
		offset += read_bytes;
		addr += PGSIZE;
	}

	/* Insert entry into vme_list */
	list_push_back(&thread_current()->mmap_list, &mmap_f->elem);

	return mapid;
}

/* Do a file memory unmapping */
void
munmap(int mapping)
{
	/* Will temporary store each object in child list. */
	struct list_elem *e;
	struct list_elem *next_e;

	for(e = list_begin(&thread_current()->mmap_list); e != list_end(&thread_current()->mmap_list); e = next_e)
	{
		/* Get next element */
		next_e = list_next(e);

		/* Get mmap_file from lost */
		struct mmap_file *mmap_f = list_entry(e, struct mmap_file, elem);
	
		/* If this mmap_file has target mapid or trying to unmap all, unmapping. */
		if(mmap_f->mapid == mapping || mapping == -1)
		{
			do_munmap(mmap_f);

			/* Close file */
			if(mmap_f->file != NULL)
			{
				lock_acquire(&filesys_lock);
				file_close(mmap_f->file);
				lock_release(&filesys_lock);
			}

			list_remove(&mmap_f->elem);
			free(mmap_f);
		}
	}
}

/* Actually free memory allocated for mmap */
void
do_munmap(struct mmap_file *mmap_f)
{
	/* Will temporary store each object in child list. */
	struct list_elem *e;
	struct list_elem *next_e;

	/* Search vme list and delete them */
	for(e = list_begin(&mmap_f->vme_list); e != list_end(&mmap_f->vme_list); e = next_e)
	{
		/* Get next element */
		next_e = list_next(e);

		/* Get VM entry */
		struct vm_entry *entry = list_entry(e, struct vm_entry, mmap_elem);

		entry->pinned = true;
		if(entry != NULL && entry->is_loaded)
		{
			if(pagedir_is_dirty(thread_current()->pagedir, entry->vaddr))
			{
				lock_acquire(&filesys_lock);
			    file_write_at(entry->file, entry->vaddr, entry->read_bytes, entry->offset);
			    lock_release(&filesys_lock);
			}

			/* Clear page allocated for VM entry */
			palloc_free_page(pagedir_get_page(thread_current()->pagedir, entry->vaddr));			
			pagedir_clear_page(thread_current()->pagedir, entry->vaddr);
		}

		/* Remove from mmap list */
		list_remove(&entry->mmap_elem);

		/* Delete selected entry from hash table */
		delete_vme(&thread_current()->vm, entry);
	}
}

/* Shutdown system */
void
sys_halt(void)
{
	shutdown_power_off();
}

/* Exit current process */
void
sys_exit(int status)
{
	struct thread *current_thread = thread_current(); //Get current thread information. This will be used to get thread name.
	printf("%s: exit(%d)\n", current_thread->name, status); //Display exit task information.
	current_thread->exit_status = status; //Store exit status into child_process descriptor.
	
	thread_exit();
}

/* Create file */
bool
sys_create(const char *file, unsigned int initial_size)
{
	lock_acquire(&filesys_lock); //lock for atomic file operation.
	bool result = filesys_create(file, initial_size);
	lock_release(&filesys_lock); //Unlock for atomic file operation.

	return result; //If success, return true. Else, return false.
}

/* Remove file */
bool
sys_remove(const char *file)
{
	lock_acquire(&filesys_lock); //lock for atomic file operation.
	bool result = filesys_remove(file);
	lock_release(&filesys_lock); //Unlock for atomic file operation.

	return result; //If success, return true. Else, return false.return result;
}

/* Execute child process */
tid_t
sys_exec(char *exec_filename)
{
	tid_t executed_process_tid = process_execute(exec_filename); //Get tid of executed process.
	struct thread *executed_process_desc = get_child_process(executed_process_tid); //Get object of correspond tid.

	if(executed_process_desc) //If tid exists, then...
	{
		sema_down(&executed_process_desc->load_sema); //Block parent process.

		if(executed_process_desc->is_load) //If successfully load
		{
			return executed_process_tid;
		}
		else //If failed to load
		{
			return -1;
		}
	}
	else //If load fail, return -1.
	{
		return -1;
	}
}

/* Wait for child process to exit */
int
sys_wait(tid_t tid)
{
	return process_wait(tid);
}

/* Open file */
int
sys_open(const char *open_filename)
{
	lock_acquire(&filesys_lock); //lock for atomic file operation.
	struct file *open_file = filesys_open(open_filename); //Get file object
	if(!open_file)
	{
		lock_release(&filesys_lock); //Unlock for atomic file operation.
		return -1;
	}

	int open_file_fd = process_add_file(open_file);
	lock_release(&filesys_lock); //Unlock for atomic file operation.

	return open_file_fd;
}

/* Get filesize of correspond file descriptor */
int
sys_filesize(int fd)
{
	lock_acquire(&filesys_lock); //lock for atomic file operation.
	struct file *target_file = process_get_file(fd); //Get file object
	if(!target_file)
	{
		lock_release(&filesys_lock); //Unlock for atomic file operation.
		return -1;
	}

	int file_size = file_length(target_file);
	lock_release(&filesys_lock); //Unlock for atomic file operation.

	return file_size;
}

/* Get data from input buffer. */
int
sys_read(int fd, char *buffer, unsigned int size)
{
	lock_acquire(&filesys_lock); //lock for atomic file operation.

	if(fd == 0) //STDIN
	{
		unsigned int i;
		for(i = 0; i < size; i++)
		{
			buffer[i] = input_getc();
		}
		lock_release(&filesys_lock); //Unlock for atomic file operation.

		return size;
	}

	
	struct file *read_file = process_get_file(fd); //Get file object
	if(!read_file)
	{
		lock_release(&filesys_lock); //Unlock for atomic file operation.
		return -1;
	}

	int read_size = file_read(read_file, buffer, size);
	lock_release(&filesys_lock); //Unlock for atomic file operation.

	return read_size;
}

/* Put data into output buffer. */
int
sys_write(int fd, char *buffer, unsigned int size)
{
	lock_acquire(&filesys_lock); //lock for atomic file operation.
	
	if(fd == 1) //STDOUT
	{
		putbuf(buffer, size);
		lock_release(&filesys_lock); //Unlock for atomic file operation.

		return size;
	}

	struct file *write_file = process_get_file(fd); //Get file object
	if(!write_file)
	{
		lock_release(&filesys_lock); //Unlock for atomic file operation.
		return -1;
	}

	int write_size = file_write(write_file, buffer, size);
	lock_release(&filesys_lock); //Unlock for atomic file operation.

	return write_size;
}

/* Move offset of file */
void
sys_seek(int fd, unsigned int position)
{
	lock_acquire(&filesys_lock); //lock for atomic file operation.

	struct file *seek_file = process_get_file(fd);
	if(!seek_file)
	{
		lock_release(&filesys_lock); //Unlock for atomic file operation.
		return;
	}

	file_seek(seek_file, (off_t)position);
	lock_release(&filesys_lock); //Unlock for atomic file operation.
}

/* Get current offset of file. */
unsigned int
sys_tell(int fd)
{
	lock_acquire(&filesys_lock); //lock for atomic file operation.

	struct file *tell_file = process_get_file(fd); //Get file object
	if(!tell_file)
	{
		lock_release(&filesys_lock); //Unlock for atomic file operation.
		return -1;
	}

	off_t offset = file_tell(tell_file);
	lock_release(&filesys_lock); //Unlock for atomic file operation.

	return offset;
}

/* Close file */
void
sys_close(int fd)
{
	lock_acquire(&filesys_lock); //lock for atomic file operation.
	process_close_file(fd);
	lock_release(&filesys_lock); //Unlock for atomic file operation.
}