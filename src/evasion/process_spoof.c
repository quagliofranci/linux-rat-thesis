#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

#define FAKE_NAME "[kworker/0:0]"

void spoof_process_name(int argc, char *argv[]) {
    // Metodo 1: sovrascrive argv[0]
    // Questo cambia il nome visibile a ps e /proc/PID/cmdline
    memset(argv[0], 0, strlen(argv[0]));
    strncpy(argv[0], FAKE_NAME, strlen(argv[0]));

    // Metodo 2: prctl PR_SET_NAME
    // Cambia il nome nel kernel — visibile a top e htop
    prctl(PR_SET_NAME, FAKE_NAME, 0, 0, 0);

    // Metodo 3: sovrascrive /proc/self/comm
    // Cambia il nome letto dagli agenti Wazuh
    FILE *f = fopen("/proc/self/comm", "w");
    if (f) {
        fprintf(f, "%s", FAKE_NAME);
        fclose(f);
    }
}

int main(int argc, char *argv[]) {
    printf("[*] PID: %d\n", getpid());
    printf("[*] Nome prima dello spoof: %s\n", argv[0]);

    spoof_process_name(argc, argv);

    printf("[*] Spoof eseguito — nome ora: %s\n", FAKE_NAME);
    printf("[*] Controlla con: ps aux | grep kworker\n");
    printf("[*] Il processo dorme per 60 secondi...\n");

    // Dorme 60 secondi per darti tempo di verificare
    sleep(60);

    return 0;
}
