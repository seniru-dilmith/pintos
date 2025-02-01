#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"      // required header file
#include "filesys/file.h"       // required header file

/* Structures for file system lock and file descriptor. */
struct lock file_system_lock;       

struct file_descriptor
{
    struct file *_file;             
    int fd;                         
    struct list_elem fd_elem;      
};


void syscall_init (void);

#endif /* userprog/syscall.h */
