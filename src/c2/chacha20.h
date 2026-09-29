/*
 * chacha20.h — Implementazione ChaCha20 (RFC 7539) self-contained
 *
 * Nessuna dipendenza esterna. Drop-in replacement per XOR 0x42.
 *
 * Uso:
 *   uint8_t key[32]   = { ... };   // chiave 256 bit condivisa
 *   uint8_t nonce[12] = { ... };   // nonce 96 bit, MAI riutilizzare con stessa chiave
 *
 *   chacha20_encrypt(out, in, len, key, nonce, 0);  // cifra
 *   chacha20_encrypt(in,  out, len, key, nonce, 0); // decifra (stesso algoritmo)
 *
 * NOTA: ChaCha20 è uno stream cipher — cifratura e decifratura sono identiche.
 * MAI usare lo stesso (key, nonce) per due messaggi diversi.
 * Generare il nonce con get_random_nonce() ad ogni invio.
 */

#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Primitiva interna                                                   */
/* ------------------------------------------------------------------ */

#define CC20_ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static inline void _cc20_quarter_round(uint32_t s[16],
                                        int a, int b, int c, int d)
{
    s[a] += s[b]; s[d] ^= s[a]; s[d] = CC20_ROTL32(s[d], 16);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = CC20_ROTL32(s[b], 12);
    s[a] += s[b]; s[d] ^= s[a]; s[d] = CC20_ROTL32(s[d],  8);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = CC20_ROTL32(s[b],  7);
}

/* Genera un blocco keystream da 64 byte (20 round = 10 double round) */
static void _cc20_block(uint8_t out[64], const uint32_t state[16])
{
    uint32_t x[16];
    int i;

    memcpy(x, state, 64);

    for (i = 0; i < 10; i++) {
        /* column rounds */
        _cc20_quarter_round(x,  0,  4,  8, 12);
        _cc20_quarter_round(x,  1,  5,  9, 13);
        _cc20_quarter_round(x,  2,  6, 10, 14);
        _cc20_quarter_round(x,  3,  7, 11, 15);
        /* diagonal rounds */
        _cc20_quarter_round(x,  0,  5, 10, 15);
        _cc20_quarter_round(x,  1,  6, 11, 12);
        _cc20_quarter_round(x,  2,  7,  8, 13);
        _cc20_quarter_round(x,  3,  4,  9, 14);
    }

    for (i = 0; i < 16; i++) {
        uint32_t v = x[i] + state[i];
        out[i*4 + 0] = (uint8_t)(v       );
        out[i*4 + 1] = (uint8_t)(v >>  8 );
        out[i*4 + 2] = (uint8_t)(v >> 16 );
        out[i*4 + 3] = (uint8_t)(v >> 24 );
    }
}

/* Legge 4 byte little-endian come uint32_t */
static inline uint32_t _cc20_u8to32le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/*  API pubblica                                                        */
/* ------------------------------------------------------------------ */

/*
 * chacha20_encrypt — cifra/decifra `len` byte
 *
 * @out     : buffer output (può coincidere con `in` per cifratura in-place)
 * @in      : buffer input
 * @len     : lunghezza in byte
 * @key     : chiave 256 bit (32 byte)
 * @nonce   : nonce 96 bit (12 byte), NON riutilizzare con stessa chiave
 * @counter : block counter iniziale (normalmente 0; usare 1 con Poly1305)
 */
static void chacha20_encrypt(uint8_t       *out,
                              const uint8_t *in,
                              size_t         len,
                              const uint8_t  key[32],
                              const uint8_t  nonce[12],
                              uint32_t       counter)
{
    uint32_t state[16];
    uint8_t  keystream[64];
    size_t   pos = 0;

    /* Costanti "expand 32-byte k" (RFC 7539 §2.1) */
    state[0]  = 0x61707865u;
    state[1]  = 0x3320646eu;
    state[2]  = 0x79622d32u;
    state[3]  = 0x6b206574u;

    /* Chiave — 8 word little-endian */
    state[4]  = _cc20_u8to32le(key +  0);
    state[5]  = _cc20_u8to32le(key +  4);
    state[6]  = _cc20_u8to32le(key +  8);
    state[7]  = _cc20_u8to32le(key + 12);
    state[8]  = _cc20_u8to32le(key + 16);
    state[9]  = _cc20_u8to32le(key + 20);
    state[10] = _cc20_u8to32le(key + 24);
    state[11] = _cc20_u8to32le(key + 28);

    /* Counter (32 bit) */
    state[12] = counter;

    /* Nonce (96 bit = 3 word little-endian) */
    state[13] = _cc20_u8to32le(nonce + 0);
    state[14] = _cc20_u8to32le(nonce + 4);
    state[15] = _cc20_u8to32le(nonce + 8);

    while (pos < len) {
        size_t block = len - pos;
        if (block > 64) block = 64;

        _cc20_block(keystream, state);
        state[12]++;   /* incrementa block counter */

        for (size_t i = 0; i < block; i++)
            out[pos + i] = in[pos + i] ^ keystream[i];

        pos += block;
    }

    /* Pulisci keystream dalla stack (sicurezza) */
    memset(keystream, 0, sizeof(keystream));
}

/*
 * get_random_nonce — genera nonce casuale da /dev/urandom
 *
 * SEMPRE chiamare questa funzione prima di ogni cifratura.
 * Fallback su timestamp+contatore se /dev/urandom non disponibile.
 */
#include <stdio.h>
#include <time.h>

static void get_random_nonce(uint8_t *nonce, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(nonce, 1, len, f) == len) {
            fclose(f);
            return;
        }
        fclose(f);
    }
    /* Fallback: timestamp + contatore statico */
    static uint32_t ctr = 0;
    uint32_t ts = (uint32_t)time(NULL);
    ctr++;
    for (size_t i = 0; i < len; i++) {
        nonce[i] = (uint8_t)(((ts >> (8 * (i % 4))) ^ (ctr >> (8 * (i % 4)))) + i);
    }
}

#endif /* CHACHA20_H */
