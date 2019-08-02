#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct lock filesys_lock; /* Added to use filesystem lock to prevent unexpected situation. */

#endif /* userprog/syscall.h */