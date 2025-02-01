#include "userprog/process.h"
#include "userprog/syscall.h"  // included syscall.h header file
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
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h" // included malloc .h header file

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *program_name) 
{
    char *name_copy;         // copy of the program name to avoid race conditions
    char *token_context;     // stores the context for parsing tokens
    char *first_token;       // holds the first token from the program name
    tid_t process_id;        // stores the process id of the created thread

    /* allocate a page to store a copy of program_name */
    name_copy = palloc_get_page(0);
    if (name_copy == NULL)    // check if memory allocation failed
        return TID_ERROR;
    
    /* copy the original program name into name_copy */
    strlcpy(name_copy, program_name, PGSIZE);

    /* allocate memory for token extraction */
    first_token = malloc(strlen(program_name) + 1);  
    if (first_token == NULL)  // ensure malloc did not fail
        return TID_ERROR;
    
    /* copy program_name into first_token for token parsing */
    strlcpy(first_token, program_name, strlen(program_name) + 1);
    
    /* extract the first token using strtok_r */
    first_token = strtok_r((char*) first_token, " ", &token_context);

    /* create a new thread to execute the extracted program */
    process_id = thread_create(first_token, PRI_DEFAULT, start_process, name_copy);
    
    /* free the allocated page if thread creation failed */
    if (process_id == TID_ERROR)
        palloc_free_page(name_copy);

    /* release the memory allocated for first_token */
    free(first_token);
    
    /* return the id of the created process */
    return process_id;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *program_name_) 
{
    char *program_name = program_name_;   // cast the argument to a string
    struct intr_frame interrupt_frame;    // create an interrupt frame for process startup
    bool load_success;                    // flag to track if loading was successful

    /* initialize interrupt frame and set segment selectors */
    memset(&interrupt_frame, 0, sizeof interrupt_frame);
    interrupt_frame.gs = interrupt_frame.fs = interrupt_frame.es = 
        interrupt_frame.ds = interrupt_frame.ss = SEL_UDSEG;  // user data segment
    interrupt_frame.cs = SEL_UCSEG;                           // user code segment
    interrupt_frame.eflags = FLAG_IF | FLAG_MBS;              // set interrupt flag and must-be-set flag

    /* attempt to load the program into memory */
    load_success = load(program_name, &interrupt_frame.eip, &interrupt_frame.esp);

    /* update thread state and signal semaphore on load completion */
    struct thread *current_thread = thread_current();   // get the current thread
    current_thread->status_load_success = load_success; // store load status in thread struct
    sema_up(&current_thread->init_sema);                // release semaphore to signal completion

    /* release allocated memory for program name */
    palloc_free_page(program_name_);
    
    /* terminate the thread if loading failed */
    if (!load_success) 
        thread_exit();

    /* start the process by simulating an interrupt return */
    /* intr_exit (defined in threads/intr-stubs.S) expects its arguments in a struct intr_frame */
    /* set the stack pointer to point to the interrupt frame and jump to intr_exit */
    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&interrupt_frame) : "memory");
    
    NOT_REACHED();  // this point should never be reached
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(tid_t child_id) {
    struct thread *current_thread = thread_current();  // get the current thread
    struct thread *child_thread = NULL;  // pointer to store the child thread if found

    /* search for the child thread with the given tid */
    struct list_elem *elem;
    for (elem = list_begin(&current_thread->child_list); 
         elem != list_end(&current_thread->child_list); 
         elem = list_next(elem)) {
         
        struct thread *temp_thread = list_entry(elem, struct thread, child_elem); 

        /* check if the current thread matches the target child tid */
        if (temp_thread->tid == child_id) {
            child_thread = temp_thread;  // store the found child thread
            break;
        }
    }

    /* if the child thread is not found, return -1 */
    if (child_thread == NULL) 
        return -1;

    /* remove the child thread from the parent's child list */
    list_remove(&child_thread->child_elem);

    /* wait for the child thread to complete execution */
    sema_down(&child_thread->pre_exit_sema);

    /* retrieve the child's exit status */
    int child_exit_status = child_thread->exit_status;

    /* release the child's exit semaphore to allow cleanup */
    sema_up(&child_thread->exit_sema);

    /* return the child's exit status */
    return child_exit_status;
}

/* Free the current process's resources. */
void
process_exit(void) 
{
    struct thread *current_thread = thread_current();  // get the current thread
    uint32_t *page_directory;  // pointer to the thread's page directory

    /* print the thread's exit message with its exit status */
    printf("%s: exit(%d)\n", current_thread->name, current_thread->exit_status);

    /* allow writing and close the process's executable file if open */
    if (current_thread->process_file != NULL) {
        file_allow_write(current_thread->process_file);
        file_close(current_thread->process_file);
    }

    /* close all open file descriptors associated with the thread */
    struct list_elem *file_elem;
    while (!list_empty(&current_thread->open_fd_list)) {
        file_elem = list_pop_front(&current_thread->open_fd_list);  // get the first file descriptor
        struct file_descriptor *fd = list_entry(file_elem, struct file_descriptor, fd_elem);
        
        /* close the file and free the file descriptor */
        file_close(fd->_file);
        list_remove(&fd->fd_elem);  // remove the descriptor from the list
        free(fd);  // free allocated memory
    }

    /* signal that the process is about to exit */
    sema_up(&current_thread->pre_exit_sema);

    /* wait for other threads to complete any final operations */
    sema_down(&current_thread->exit_sema);

    /* switch to the kernel page directory and destroy the thread's page directory */
    page_directory = current_thread->pagedir;
    if (page_directory != NULL) {
        /* set the thread's page directory to NULL to prevent switching back */
        current_thread->pagedir = NULL;
        pagedir_activate(NULL);  // activate the base page directory
        pagedir_destroy(page_directory);  // destroy the thread's page directory
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

static bool setup_stack (void **stack_pointer, const char *program_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load(const char *program_name, void (**entry_point)(void), void **stack_pointer) 
{
    struct thread *current_thread = thread_current();  // get the current thread
    struct Elf32_Ehdr elf_header;  // store the ELF header
    struct file *program_file = NULL;  // file pointer for the program
    off_t offset;
    bool load_success = false;
    int header_index;
    char *thread_name = current_thread->name;  // use the thread's name as the file name

    /* create and activate a new page directory for the thread */
    current_thread->pagedir = pagedir_create();
    if (current_thread->pagedir == NULL)
        goto cleanup;
    process_activate();

    /* open the executable file */
    program_file = filesys_open(thread_name);
    if (program_file == NULL) {
        printf("load: %s: open failed\n", thread_name);
        goto cleanup;
    }

    /* read and validate the ELF header */
    if (file_read(program_file, &elf_header, sizeof elf_header) != sizeof elf_header ||
        memcmp(elf_header.e_ident, "\177ELF\1\1\1", 7) != 0 ||
        elf_header.e_type != 2 || 
        elf_header.e_machine != 3 || 
        elf_header.e_version != 1 || 
        elf_header.e_phentsize != sizeof(struct Elf32_Phdr) || 
        elf_header.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", thread_name);
        goto cleanup;
    }

    /* read each program header */
    offset = elf_header.e_phoff;
    for (header_index = 0; header_index < elf_header.e_phnum; header_index++) {
        struct Elf32_Phdr program_header;

        if (offset < 0 || offset > file_length(program_file))
            goto cleanup;
        file_seek(program_file, offset);

        if (file_read(program_file, &program_header, sizeof program_header) != sizeof program_header)
            goto cleanup;
        offset += sizeof program_header;

        switch (program_header.p_type) {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* ignore unsupported segment types */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto cleanup;  // unsupported segment types
            case PT_LOAD:
                if (validate_segment(&program_header, program_file)) {
                    bool writable = (program_header.p_flags & PF_W) != 0;
                    uint32_t file_page = program_header.p_offset & ~PGMASK;
                    uint32_t memory_page = program_header.p_vaddr & ~PGMASK;
                    uint32_t page_offset = program_header.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;

                    if (program_header.p_filesz > 0) {
                        /* read part of the segment from the file */
                        read_bytes = page_offset + program_header.p_filesz;
                        zero_bytes = ROUND_UP(page_offset + program_header.p_memsz, PGSIZE) - read_bytes;
                    } else {
                        /* segment is entirely zeroed */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP(page_offset + program_header.p_memsz, PGSIZE);
                    }

                    if (!load_segment(program_file, file_page, (void *)memory_page,
                                      read_bytes, zero_bytes, writable))
                        goto cleanup;
                } else {
                    goto cleanup;
                }
                break;
        }
    }

    /* set up the stack */
    if (!setup_stack(stack_pointer, program_name))
        goto cleanup;

    /* set the entry point to the program's entry address */
    *entry_point = (void (*)(void)) elf_header.e_entry;

    load_success = true;

cleanup:
    /* close the program file if loading failed */
    if (!load_success)
        file_close(program_file);
    else {
        /* prevent the file from being modified while in use */
        current_thread->process_file = program_file;
        file_deny_write(program_file);
    }

    return load_success;
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
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

#define ARG_SIZE_DEFAULT 3  // default size for argument array

/* create a minimal stack by mapping a zeroed page at the top of user virtual memory */
static bool
setup_stack(void **stack_ptr, const char *program_name) 
{
    uint8_t *kernel_page;
    bool setup_success = false;

    char *program_copy;
    char *arg_token, *save_context;
    int arg_count = 0;
    int total_bytes = 0;
    char **arg_array;
    char **arg_address_array;

    /* allocate a page for the stack and zero it */
    kernel_page = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kernel_page != NULL) {
        setup_success = install_page(((uint8_t *) PHYS_BASE) - PGSIZE, kernel_page, true);

        if (setup_success) {
            *stack_ptr = PHYS_BASE;

            /* create a copy of the program name to parse */
            program_copy = palloc_get_page(0);
            if (program_copy == NULL)
                return TID_ERROR;

            strlcpy(program_copy, program_name, PGSIZE);

            /* allocate space for the initial argument array */
            arg_array = malloc(ARG_SIZE_DEFAULT * sizeof(char *));
            
            /* parse the program name into tokens */
            for (
                arg_token = strtok_r(program_copy, " ", &save_context); 
                arg_token != NULL; 
                arg_token = strtok_r(NULL, " ", &save_context)
            ) {
                arg_count++;
                if (arg_count > ARG_SIZE_DEFAULT) {
                    /* reallocate space if more arguments are found */
                    arg_array = realloc(arg_array, arg_count * sizeof(char *));
                }
                arg_array[arg_count - 1] = arg_token;
            }

            int arg_length;
            arg_address_array = malloc(arg_count * sizeof(char *));
            
            /* copy arguments to the stack in reverse order */
            for (int i = arg_count; i > 0; i--) {
                arg_length = strlen(arg_array[i - 1]) + 1;
                total_bytes += arg_length;
                *stack_ptr -= arg_length;
                arg_address_array[i - 1] = *stack_ptr;
                memcpy(*stack_ptr, arg_array[i - 1], arg_length);
            }

            /* apply word alignment to the stack */
            int alignment = total_bytes % 4;
            if (alignment != 0) {
                alignment = 4 - alignment;
                *stack_ptr -= alignment;
                memset(*stack_ptr, 0, alignment);
            }

            /* push a null pointer sentinel */
            *stack_ptr -= sizeof(char *);
            total_bytes += sizeof(char *);
            *(char *) *stack_ptr = 0;

            /* push addresses of each argument */
            for (int i = arg_count; i > 0; i--) {
                *stack_ptr -= sizeof(char *);
                total_bytes += sizeof(char *);
                *(int *) *stack_ptr = (unsigned) arg_address_array[i - 1];
            }

            /* store the address of the first argument array */
            void *arg_start = *stack_ptr;
            *stack_ptr -= sizeof(char **);
            total_bytes += sizeof(char **);
            memcpy(*stack_ptr, &arg_start, sizeof(char **));

            /* push the argument count */
            *stack_ptr -= sizeof(int);
            total_bytes += sizeof(int);
            memcpy(*stack_ptr, &arg_count, sizeof(int));

            /* push a fake return address */
            *stack_ptr -= sizeof(void *);
            total_bytes += sizeof(void *);

            /* clean up allocated memory */
            free(arg_address_array);
            free(arg_array);
            palloc_free_page(program_copy);
        } else {
            /* free the kernel page if setup failed */
            palloc_free_page(kernel_page);
        }
    }
    return setup_success;
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
