#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h" /* Added to use malloc */
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Added to use VM */
#include "vm/page.h"
#include "vm/swap.h"
#include "vm/frame.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void argument_stack(const char **parse, const int arg_count, void **esp);
void remove_child_process(struct thread *child);

void munmap(int mapping);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  char fn_copy_more[256]; /* Added to eliminate segmentation fault. */
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;

  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (fn_copy_more, file_name, PGSIZE);

  /* Used for 3rd argument in 'strtok_r' function.*/
  char *strtok_save_ptr;

  /* get 1st token from 'file_name' */
  char *thread_name = strtok_r(fn_copy_more, " ", &strtok_save_ptr);
  if(!thread_name) /* Exit if tokenizing task fails. */
    return TID_ERROR;

  /* Create a new thread to execute FILE_NAME. */
  /* Insert 'thread_name' tokenized from 'file_name' into 'thread_create' function */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
  {
    palloc_free_page (fn_copy);
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = (char*)file_name_; /* Type Casting */
  struct intr_frame if_;
  bool success;

  /* Initialize VM */
  vm_init(&thread_current()->vm);

  /* Initialize mmap */
  thread_current()->mapid = 0;
  list_init(&thread_current()->mmap_list);

  /*
    Temporary variable that store tokenized arguments from 'file_name' variable.
    This variable will be used in 'argument_stack' function to store argument into stack.
  */
  char **parse = (char**)malloc(sizeof(char*)); //parsed tokens will be stored here temporary.
  int arg_count = 0; //The number of parsed arguments.
  char *temp_parsed; //The variable that store one parsed argument temporary.
  char *strtok_save_ptr; //3rd argument of strtok_r function.

  /*
    Before insert into stack, seperate 'file_name' and insert into 'parse' Array.
  */
  for(temp_parsed = strtok_r(file_name, " ", &strtok_save_ptr); temp_parsed; temp_parsed = strtok_r(NULL, " ", &strtok_save_ptr))
  {
    parse = (char**)realloc(parse, sizeof(char*)*(arg_count + 1));
    parse[arg_count] = (char*)malloc(sizeof(char)*strlen(temp_parsed));
    strlcpy(parse[arg_count], temp_parsed, sizeof(char)*(strlen(temp_parsed) + 1)); //To prevent shallow copy, strlcpy function be used.
    arg_count++;
  }

  /* 1st token parsed from 'file_name' that will be passed to 'load' function. */
  char *load_file_name = parse[0];

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (load_file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);

  if (!success)
  {
    sema_up(&thread_current()->load_sema); /* Unblock parent process */
    thread_exit ();
  }
  else
  {
    thread_current()->is_load = 1; /* flag that successfully load. */
    sema_up(&thread_current()->load_sema); /* Unblock parent process */
  }

  /* Store arguments into stack */
  argument_stack(parse , arg_count , &if_.esp);

  /* Free dynamically allocated memory used for parsing. */
  arg_count--;
  while(arg_count >= 0)
  {
    free(parse[arg_count]);
    arg_count--;
  }
  free(parse);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

void
argument_stack(const char **parse, const int arg_count, void **esp)
{
  int i, j;
  unsigned int argv_addr_store[arg_count];

  for(i = arg_count - 1; i >= 0; i--)
  {
    /* Inserting argv data into stack by 'char' data size. */
    for(j = strlen(parse[i]); j >= 0; j--)
    {
      *esp -= 1;
      **(char**)esp = parse[i][j];
    }

    /* Store address of string temporary. This address will be inserted in stack too. */
    argv_addr_store[i] = (unsigned int)(*esp);
  }

  /* Word Size Align */
  *esp = (unsigned int)*esp & 0xfffffffc;

  /* NULL argv set. */
  *esp -= 4;
  memset(*esp, 0, sizeof(unsigned int));

  /* Insert each address of inserted argument string. */
  for(i = arg_count - 1; i >= 0; i--)
  {
    *esp -= 4;
    *(unsigned int*)(*esp) = argv_addr_store[i];
  }

  /* insert address of '**argv'. This is equal to *argv[0], so code looks like below. */
  *esp -= 4;
  *(unsigned int*)(*esp) = (unsigned int)(*esp) + 4;

  /* Insert argc data into stack. */
  *esp -= 4;
  *(unsigned int*)(*esp) = (unsigned int)arg_count;

  /* Insert Fake Address */
  *esp -= 4;
  memset(*esp, 0, sizeof(unsigned int));
}

struct thread
*get_child_process(int pid)
{
  struct thread *parent = thread_current(); /* Get current process object */
  struct thread *child = NULL; /* Initialize child process object. */

  struct list_elem *e; /* Will temporary store each object in child list. */

  for(e = list_begin(&parent->child_list); e != list_end(&parent->child_list); e = list_next(e))
  {
    struct thread *node = list_entry(e, struct thread, child_elem); //Get each object in list.
    if(node->tid == pid) //If find target child...
    {
      child = node;
      break;
    }
  }

  return child; /* If failed to find child, return NULL. Else, return correspond child process object. */
}

/* The function that remove child process from list and free allocated memory. */
void 
remove_child_process(struct thread *child)
{
  list_remove(&child->child_elem); //Remove correspond child element from child list.
  palloc_free_page(child); //Clear allocated memory for child process descriptor.
}

/* This function generates file descriptor number. */
int
process_add_file(struct file *f)
{
  struct file **fd_table = thread_current()->file_desc_table; //Get file descriptor table.
  int fd_count = thread_current()->file_desc_count; //Get fd count.

  fd_table[fd_count] = f; /* Insert file  */
  thread_current()->file_desc_count += 1; //Increase fd count.

  return fd_count;
}

/* This function searches fd table and returns address of file object. */
struct file
*process_get_file(int fd)
{
  if(fd < 2 || fd > thread_current()->file_desc_count)
    return NULL;
  else
    return thread_current()->file_desc_table[fd]; //Returns matched file object.
}

/* This function closes related file and initialize correpond fd table. */
void
process_close_file(int fd)
{
  if(fd >= 2 && fd <= thread_current()->file_desc_count && thread_current()->file_desc_table[fd] != NULL)
  {
    file_close(thread_current()->file_desc_table[fd]); //Close target file.
    thread_current()->file_desc_table[fd] = NULL; //Set target table to NULL.
  }
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *child = get_child_process(child_tid); //Get child process object.

  if(child) //Target child exists.
  {
    sema_down(&child->exit_sema); //sema down for child process. This will block parent process.

    int exit_status = child->exit_status; //Get exit status of child.
    remove_child_process(child); //Remove child
    return exit_status;
  }
  else //Failed to find child. In this case, return -1.
  {
    return -1;
  }
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* close all files and clear allocated memory for file descriptor table */
  int i;
  for(i = 2; i < cur->file_desc_count; i++) //Remove all files that opened from that process.
  {
    process_close_file(i);
  }
  palloc_free_page(cur->file_desc_table); //Clear memory for file descriptor table.

  munmap(-1); //Clear all mmaped files
  vm_destroy(&cur->vm); //Clear allocated memory for VM

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  lock_acquire(&filesys_lock);

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_close (file);
  lock_release(&filesys_lock);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);

  /* Creage VM entry until no more read bytes and zero bytes */
  while (read_bytes > 0 || zero_bytes > 0) 
  {
    /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Create new VM entry */
    struct vm_entry *entry = (struct vm_entry*)malloc(sizeof(struct vm_entry));

    /* Initialize VM entry */
    entry->type = VM_BIN;
    entry->writable = writable;
    entry->is_loaded = false;
    entry->file = file;
    entry->offset = ofs;
    entry->vaddr = upage;
    entry->read_bytes = page_read_bytes;
    entry->zero_bytes = page_zero_bytes;
    entry->pinned = false;

    /* Insert VM entry into VM hash table. */
    if(insert_vme(&thread_current()->vm, entry) == false)
      return false;

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    ofs += page_read_bytes;
    upage += PGSIZE;
  }

  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  //uint8_t *kpage;
  bool success = false;

  /* Create new VM entry */
  struct vm_entry *entry = (struct vm_entry*)malloc(sizeof(struct vm_entry));
  if(entry == NULL)
    return success;

  /* Initialize VM */
  entry->vaddr = ((uint8_t *) PHYS_BASE) - PGSIZE;
  entry->writable = true;
  entry->type = VM_ANON;
  entry->is_loaded = true;
  entry->pinned = false;

  /* Create new page */
  struct page *page = alloc_page(PAL_USER | PAL_ZERO);
  page->vme = entry; /* Set vme into page */
  void *kaddr = page->kaddr; /* Set kaddr */

  /* Insert VM entry into VM hash table. */
  if(insert_vme(&thread_current()->vm, entry) == false)
    return false;

  /* Perform install page and get result */
  success = install_page(((uint8_t *) PHYS_BASE) - PGSIZE, kaddr, true);
  if(success)
  {
    *esp = PHYS_BASE;
  }
  else
  {
    free_page(page);
    return success;
  }

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* This function will handle page fault. */
bool handle_mm_fault(struct vm_entry *vme)
{
  /* If VM entry already loaded, it should not be here. */
  if(vme->is_loaded == true)
    return false;

  /* Allocate memory for 1 page */
  struct page *page = alloc_page(PAL_USER);
  page->vme = vme;
  void *kaddr = page->kaddr;

  /* If failed to load page, free page */
  switch(vme->type)
  {
    case VM_BIN:
      if(!load_file(kaddr, vme))
      {
        free_page(kaddr);
        return false;
      }
      break;

    case VM_FILE:
      if(!load_file(kaddr, vme))
      {
        free_page(kaddr);
        return false;
      }
      break;

    case VM_ANON:
      swap_in(vme->swap_slot, kaddr);
      break;
  }

  /* If success to load page, map to physical and VM. */
  install_page(vme->vaddr, kaddr, vme->writable);
  vme->is_loaded = true;

  return true;
}

bool expand_stack(void *addr)
{
  /* Grow limit already checked. */
  /*
    Round down to nearest page boundary.
    static inline void *pg_round_down (const void *va) {
      return (void *) ((uintptr_t) va & ~PGMASK);
    }
  */

  /* Check if the size of stack is smaller than MAX size */
  if((size_t)(PHYS_BASE - pg_round_down(addr)) > MAX_STACK_SIZE)
    return false;

  /* Create new VM entry for expanded stack space. */
  struct vm_entry *entry = (struct vm_entry*)malloc(sizeof(struct vm_entry));
  if(entry == NULL) /* Failed to allocate */
    return false;

  /* Initialize VM entry contents */
  entry->vaddr = pg_round_down(addr);
  entry->writable = true;
  entry->type = VM_ANON;
  entry->pinned = true;

  /* Create new page */
  struct page* page = alloc_page(PAL_USER | PAL_ZERO);
  if(page == NULL) /* If failed to create new page, rollback. */
  {
    free(entry);
    return false;
  }

  /* Set VM entry into page */
  page->vme = entry;

  /* If failed to insert VM entry into VM hash table, rollback. */
  if(!insert_vme(&thread_current()->vm, entry))
  {
    free(entry);
    free_page(page->kaddr);
    return false;
  }

  /* If failed to link vaddr with kaddr, rollback. */
  if(!install_page(entry->vaddr, page->kaddr, entry->writable))
  {
    free(entry);
    free_page(page->kaddr);
    return false;
  }

  /* Set final value */
  entry->is_loaded = true;
  entry->pinned = false;

  return true;
}