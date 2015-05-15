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
	check_address(esp, esp);

	unsigned int *argument[5]; //Arguments for system call will be stored temporary.
	int system_call_number = *(int*)esp; //Recognize system call number. This will be used for switch case block.

	esp = esp + 1; //Increase stack pointer value.
	check_address(esp, esp); /* Check again */

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
				check_valid_buffer(buffer, size, esp, false);

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
				check_valid_buffer(buffer, size, esp, true);

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

	struct vm_entry *entry = find_vme(addr);
	if(entry)
	{
		entry->pinned = true;
		handle_mm_fault(entry);
	}
	else if((size_t)addr < (size_t)(PHYS_BASE - MAX_STACK_SIZE))
		sys_exit(-1);

	if(entry->is_loaded == false)
		sys_exit(-1);

	return entry;
}

void
check_valid_buffer(void *buffer, unsigned int size, void *esp, bool to_write)
{
	unsigned int i;
	struct vm_entry *entry;

	for(i = 0; i < size; i++)
	{
		entry = check_address(buffer, esp);
		if(entry != NULL && (to_write == true && entry->writable == false))
		{
			sys_exit(-1);
		}
		buffer = buffer + 1;
	}
}

void
check_valid_string(const void *str, void *esp)
{
	void *ptr = (void*)str;
	struct vm_entry *entry UNUSED;

	entry = check_address(ptr, esp);

	while(*(char*)ptr != '\0')
	{
		struct vm_entry *entry UNUSED;
		entry = check_address(ptr, esp);

		ptr = ptr + 1;
	}

	entry = check_address(ptr, esp);
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