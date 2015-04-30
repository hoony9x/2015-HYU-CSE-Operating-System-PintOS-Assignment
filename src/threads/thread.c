#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/malloc.h" /* Added to use malloc function */
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/fixed_point.h" /* Added to use floating point operation */
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Added to use Advanced Scheduling */
#define NICE_DEFAULT 0
#define NICE_MAX 20
#define NICE_MIN -20
#define RECENT_CPU_DEFAULT 0
#define LOAD_AVG_DEFAULT 0

int load_avg;

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Added to use sleep list. This is the list of process in sleep state. */
static struct list sleep_list;

/* Added to check awake time */
int64_t next_tick_to_awake = INT64_MAX;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

void
thread_sleep(int64_t ticks) //Will be used to sleep process.
{
  struct thread *cur = thread_current(); //Get current process
  if(cur != idle_thread) //If not idle
  {
    enum intr_level old_level;
    old_level = intr_disable (); //Diable interrupt

    cur->my_awake_tick = ticks; //Set my awake tick
    list_push_back(&sleep_list, &cur->elem); //Push into sleep list
    update_next_tick_to_awake(); //Update next awake tick

    thread_block(); //Block current process
    intr_set_level (old_level); //Enable interrupt
  }
}

void
thread_awake(int64_t ticks)
{
  struct list_elem *e; /* Will temporary store each object in child list. */

  /* Search all elements in sleep list */
  for(e = list_begin(&sleep_list); e != list_end(&sleep_list);)
  {
    struct thread *t = list_entry(e, struct thread, elem); //Get each object in list.
    e = list_next(e);

    if(t->my_awake_tick <= ticks) //If it is time to awake
    {
      list_remove(&t->elem); //Remove from sleep list.
      thread_unblock(t); //unblock
    }
    else //If it is not time to awake
    {
      update_next_tick_to_awake(); //Just update next tick
    }
  }
}

void
update_next_tick_to_awake()
{
  int64_t min_tick = INT64_MAX; //For check which tick is minimum.
  struct list_elem *e; /* Will temporary store each object in child list. */

  /* Search all elements in sleep list */
  for(e = list_begin(&sleep_list); e != list_end(&sleep_list); e = list_next(e))
  {
    struct thread *t = list_entry(e, struct thread, elem); //Get each object in list.
    if(t->my_awake_tick < min_tick) //make min_tick variable smallist.
      min_tick = t->my_awake_tick;
  }

  next_tick_to_awake = min_tick; //Update next_tick_to_awake variable with minimum tick.
}

int64_t
get_next_tick_to_awake(void) //Just return current next awake tick value;
{
  return next_tick_to_awake;
}

void
donate_priority(void) //Donate priority
{
  struct thread *cur_thread = thread_current(); //Get current process info
  struct lock *cur_lock = cur_thread->wait_on_lock; //Get lock info
  int depth = 0;

  //Search for nested donation
  while(cur_lock != NULL && cur_lock->holder != NULL && depth < 8)
  {
    if(cur_lock->holder->priority > cur_thread->priority)
      break;

    cur_lock->holder->priority = cur_thread->priority; //donate priority
    cur_thread = cur_lock->holder; //move to next process
    cur_lock = cur_thread->wait_on_lock; //get new lock

    depth++;
  }
}

void
remove_with_lock(struct lock *lock) //when release lock, check donation list and do a proper job.
{
  struct list_elem *e; /* Will temporary store each object in child list. */
  struct list *target_donation_list = &thread_current()->donations;

  if(list_empty(target_donation_list)) //If list is empty, quit
    return;

  /* Search all elements in donation list */
  for(e = list_begin(target_donation_list); e != list_end(target_donation_list);)
  {
    struct thread *t = list_entry(e, struct thread, donation_elem); //Get each object in list.
    e = list_next(e);
    
    if(t->wait_on_lock == lock)
      list_remove(&t->donation_elem); //remove entry that has same lock
  }
}

void
refresh_priority(void)
{
  struct thread *cur = thread_current(); //Get current process
  cur->priority = cur->init_priority; //Restore initial priority

  if(list_empty(&cur->donations)) //If list is empty, quit
    return;

  struct list_elem *e;
  int highest_priority_value = PRI_MIN; //This variable will be used to check maximum priority in donation list

  /* Search all elements in sleep list */
  for(e = list_begin(&cur->donations); e != list_end(&cur->donations); e = list_next(e))
  {
    struct thread *t = list_entry(e, struct thread, donation_elem); //Get each object in list.
    
    if(t->priority > highest_priority_value)
      highest_priority_value = t->priority; //Update highest_priority_value with maximum value
  }

  if(highest_priority_value > cur->priority)
    cur->priority = highest_priority_value; //If maximum priority in donation list is higher than current priority, update.
}

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&sleep_list); /* Added to use sleep waiting */
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Added to use Advanced Scheduling */
  load_avg = LOAD_AVG_DEFAULT;

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority, thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);


  /* Implement file descriptor table */
  t->file_desc_table = palloc_get_page(0);
  t->file_desc_count = 2;

  /* Implement process hierarchy */
  t->parent_thread = thread_current();
  t->is_load = 0;
  t->is_exit = 0;

  /* Initialize child list */
  list_init(&t->child_list);

  /* Initialize each semaphore */
  sema_init(&t->load_sema, 0);
  sema_init(&t->exit_sema, 0);

  /* Push child into child list. */
  list_push_back(&t->parent_thread->child_list, &t->child_elem);

  /* Add to run queue. */
  thread_unblock (t);

  /* Compare priority and if new process's priority is higher then current process, yield. */
  if(thread_current()->priority < t->priority)
    thread_yield();

  return tid;
}

void test_max_priority(void)
{
  /* Check if ready_list is empty. */
  if(list_empty(&ready_list))
    return;

  /* yield current process */
  if(thread_current() != idle_thread)
    thread_yield();
}

/* This function will be used for sorting. */
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
  const struct thread *first = list_entry(a, struct thread, elem);
  const struct thread *second = list_entry(b, struct thread, elem);

  if(first->priority > second->priority)
    return true;
  else
    return false;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);

  /* Make ready list in ordered state. */
  list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL);

  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);

  /* If thread name is main(thus, if this thread is init thread), do not sema up this. */
  if(strcmp(thread_current()->name, "main")) //If thread is not "main" process, sema up.
  {
    sema_up(&thread_current()->exit_sema);
  }

  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();

  /* Make push in ordered state. */
  if (cur != idle_thread)
    list_insert_ordered(&ready_list, &cur->elem, cmp_priority, NULL);

  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  if(!thread_mlfqs) /* if thread use mlfqs, do not use donation. */
  {
    enum intr_level old_level = intr_disable();

    struct thread *cur = thread_current(); //Get current process info
    int old_priority = cur->priority; //Temporary store last priority
    cur->init_priority = new_priority; //Update with new priority
    refresh_priority(); //Refresh

    //Compare old priority and current priority and if not same, do something.
    if(old_priority < cur->priority)
    {
      donate_priority();
    }
    else if(old_priority > cur->priority)
    {
      test_max_priority();
    }

    intr_set_level(old_level);
  }
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) 
{
  enum intr_level old_level = intr_disable();

  thread_current()->nice = nice; /* Set new nice value */
  mlfqs_priority(thread_current()); /* Recalculate priority of current thread */
  test_max_priority(); /* Scheduling */

  intr_set_level (old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  enum intr_level old_level = intr_disable();
  int nice_value = thread_current()->nice; /* Get current nice value */
  intr_set_level (old_level);

  return nice_value;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  enum intr_level old_level = intr_disable();
  int cur_load_avg_val = fp_to_int_round(mult_mixed(load_avg, 100)); /* PintOS requires to multiply with 100 */
  intr_set_level(old_level);

  return cur_load_avg_val;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  enum intr_level old_level = intr_disable ();
  int cur_recent_cpu_val = fp_to_int_round(mult_mixed(thread_current()->recent_cpu, 100)); /* Pintos requires to multiply with 100 */
  intr_set_level (old_level);
  
  return cur_recent_cpu_val;
}

void
mlfqs_priority(struct thread *t)
{
  if(t != idle_thread)
  {
    /* Get each value and convert them into fixed point value */
    int max_priority = int_to_fp(PRI_MAX);
    int recent_cpu_divided = div_mixed(t->recent_cpu, 4);
    int niceval_doubled = 2 * t->nice;

    /* Calculate priority value */
    int temp = sub_fp(max_priority, recent_cpu_divided);
    temp = sub_mixed(temp, niceval_doubled);

    /* Store new priority value */
    t->priority = fp_to_int(temp);

    /* Check if priority value is in range */
    if(t->priority < PRI_MIN) t->priority = PRI_MIN;
    if(t->priority > PRI_MAX) t->priority = PRI_MAX;
  }
}

void
mlfqs_recent_cpu(struct thread *t)
{
  if(t != idle_thread)
  {
    /* Get load average value and convert to fixed point value */
    int load_avg_doubled = mult_mixed(load_avg, 2);

    /* Calculate and store value into recent cpu variable */
    int temp = div_fp(load_avg_doubled, add_mixed(load_avg_doubled, 1));
    temp = mult_fp(temp, t->recent_cpu);
    t->recent_cpu = add_mixed(temp, t->nice);
  }
}

void
mlfqs_load_avg(void)
{
  /* Get current amount of threads */
  int ready_list_size = list_size(&ready_list);
  if(thread_current() != idle_thread) /* If not idle thread, increment 1 */
    ready_list_size++;

  /* Get load average and divide */
  int divided_load_avg = mult_fp(load_avg, div_mixed(int_to_fp(59), 60));

  /* Divide ready_list_size by 60 */
  ready_list_size = div_mixed(int_to_fp(ready_list_size), 60);

  /* Get new load average */
  load_avg = add_fp(divided_load_avg, ready_list_size);

  /* Check if load_avg is non-negative value */
  ASSERT(load_avg >= 0);
}

void
mlfqs_increment(void)
{
  /* If not idle thread, increse recent cpu value */
  if(thread_current() != idle_thread)
    thread_current()->recent_cpu = add_mixed(thread_current()->recent_cpu, 1);
}

void
mlfqs_recalc(void)
{
  struct list_elem *e;
  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
  {
    struct thread *t = list_entry(e, struct thread, allelem);
    mlfqs_recent_cpu(t);
    mlfqs_priority(t);
  }
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;
  list_push_back (&all_list, &t->allelem);

  /* Initialize child list */
  list_init(&t->child_list);

  /* Initialize things related to priority donation */
  list_init(&t->donations);
  t->wait_on_lock = NULL;
  t->init_priority = priority;

  /* Initialize variables for Advanced Scheduling */
  t->nice = NICE_DEFAULT;
  t->recent_cpu = RECENT_CPU_DEFAULT;
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      //palloc_free_page (prev); /* Instructor wants to delete this line. */
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
