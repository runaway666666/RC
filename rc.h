#ifndef RC_H
#define RC_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ===== Helper: Hex encode/decode for display =====
static void to_hex(const unsigned char* data, size_t len, char* out) {
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[2*i] = hex_digits[(data[i] >> 4) & 0xF];
        out[2*i+1] = hex_digits[data[i] & 0xF];
    }
    out[2*len] = 0;
}
static int from_hex(const char* hex, unsigned char* out, size_t outlen) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || outlen < len/2) return 0;
    for (size_t i = 0; i < len; i += 2) {
        unsigned int byte;
        if (sscanf(&hex[i], "%2x", &byte) != 1) return 0;
        out[i/2] = (unsigned char)byte;
    }
    return 1;
}

// ========== RC2 ==========
#define RC2_BLOCK_SIZE 8
typedef struct {
    uint16_t K[64];
} RC2_CTX;

static void RC2_key_expand(RC2_CTX* ctx, const unsigned char* key, size_t keylen) {
    static const uint8_t PI_SUBST[256] = {
        217,120,249,196,25,221,181,237,40,233,253,121,74,160,216,157,198,126,55,131,43,118,83,142,98,76,100,136,68,139,251,162,
        23,154,89,245,135,179,79,19,97,69,109,141,9,129,125,50,189,143,64,235,134,183,123,11,240,149,33,34,92,107,78,130,
        84,214,101,147,206,96,178,28,115,86,192,20,167,140,241,220,18,186,247,120,234,75,0,26,197,62,94,252,219,203,117,35,
        11,32,57,177,33,88,237,149,56,87,174,20,125,136,149,14,157,46,137,240,13,236,141,60,82,13,183,160,160,223,224,217,
        95,112,128,154,107,221,224,124,155,197,255,135,144,251,183,142,115,189,218,157,61,114,175,188,24,88,69,222,179,20,143,234,
        198,93,34,178,203,131,33,135,139,233,139,49,55,99,212,213,38,237,101,73,125,149,54,172,251,227,14,50,113,221,27,63,
        46,221,99,169,197,115,77,193,34,106,59,86,170,24,38,176,238,87,132,10,242,92,190,211,91,219,194,146,76,120,215,107,
        60,241,82,62,2,129,41,159,36,205,111,41,244,224,21,37,136,101,63,20,153,243,234,49,102,222,110,78,161,172,54,99
    };
    uint8_t L[128] = {0};
    size_t T = keylen;
    memcpy(L, key, T);
    for (size_t i = T; i < 128; ++i)
        L[i] = PI_SUBST[(L[i-1] + L[i-T]) & 0xFF];
    for (size_t i = 0; i < 64; ++i)
        ctx->K[i] = L[2*i] + (L[2*i+1] << 8);
}
static void RC2_block_encrypt(const RC2_CTX* ctx, unsigned char* block) {
    uint16_t x[4];
    for (int i = 0; i < 4; ++i)
        x[i] = block[2*i] + (block[2*i+1] << 8);
    int j = 0;
    for (int r = 0; r < 16; ++r) {
        x[0] = (x[0] + ((x[1] & ~x[3]) + (x[2] & x[3]) + ctx->K[j++])) & 0xFFFF;
        x[0] = (x[0] << 1) | (x[0] >> 15);
        x[1] = (x[1] + ((x[2] & ~x[0]) + (x[3] & x[0]) + ctx->K[j++])) & 0xFFFF;
        x[1] = (x[1] << 2) | (x[1] >> 14);
        x[2] = (x[2] + ((x[3] & ~x[1]) + (x[0] & x[1]) + ctx->K[j++])) & 0xFFFF;
        x[2] = (x[2] << 3) | (x[2] >> 13);
        x[3] = (x[3] + ((x[0] & ~x[2]) + (x[1] & x[2]) + ctx->K[j++])) & 0xFFFF;
        x[3] = (x[3] << 5) | (x[3] >> 11);
        if (r == 4 || r == 10)
            for (int i = 0; i < 4; ++i)
                x[i] = (x[i] + ctx->K[x[(i+3)%4] & 63]) & 0xFFFF;
    }
    for (int i = 0; i < 4; ++i) {
        block[2*i] = x[i] & 0xFF;
        block[2*i+1] = x[i] >> 8;
    }
}
static void RC2_block_decrypt(const RC2_CTX* ctx, unsigned char* block) {
    uint16_t x[4];
    for (int i = 0; i < 4; ++i)
        x[i] = block[2*i] + (block[2*i+1] << 8);
    int j = 63;
    for (int r = 15; r >= 0; --r) {
        if (r == 4 || r == 10)
            for (int i = 3; i >= 0; --i)
                x[i] = (x[i] - ctx->K[x[(i+3)%4] & 63]) & 0xFFFF;
        x[3] = ((x[3] >> 5) | (x[3] << 11)) & 0xFFFF;
        x[3] = (x[3] - ((x[0] & ~x[2]) + (x[1] & x[2]) + ctx->K[j--])) & 0xFFFF;
        x[2] = ((x[2] >> 3) | (x[2] << 13)) & 0xFFFF;
        x[2] = (x[2] - ((x[3] & ~x[1]) + (x[0] & x[1]) + ctx->K[j--])) & 0xFFFF;
        x[1] = ((x[1] >> 2) | (x[1] << 14)) & 0xFFFF;
        x[1] = (x[1] - ((x[2] & ~x[0]) + (x[3] & x[0]) + ctx->K[j--])) & 0xFFFF;
        x[0] = ((x[0] >> 1) | (x[0] << 15)) & 0xFFFF;
        x[0] = (x[0] - ((x[1] & ~x[3]) + (x[2] & x[3]) + ctx->K[j--])) & 0xFFFF;
    }
    for (int i = 0; i < 4; ++i) {
        block[2*i] = x[i] & 0xFF;
        block[2*i+1] = x[i] >> 8;
    }
}
static size_t RC2_Encrypt(const char *key, const char *plaintext, unsigned char *ciphertext) {
    RC2_CTX ctx;
    size_t keylen = strlen(key);
    size_t ptlen = strlen(plaintext);
    RC2_key_expand(&ctx, (const unsigned char*)key, keylen);
    size_t num_blocks = (ptlen + RC2_BLOCK_SIZE - 1) / RC2_BLOCK_SIZE;
    for (size_t i = 0; i < num_blocks; ++i) {
        unsigned char block[RC2_BLOCK_SIZE] = {0};
        size_t block_len = (ptlen - i*RC2_BLOCK_SIZE > RC2_BLOCK_SIZE) ? RC2_BLOCK_SIZE : (ptlen - i*RC2_BLOCK_SIZE);
        memcpy(block, plaintext + i*RC2_BLOCK_SIZE, block_len);
        RC2_block_encrypt(&ctx, block);
        memcpy(ciphertext + i*RC2_BLOCK_SIZE, block, RC2_BLOCK_SIZE);
    }
    return num_blocks * RC2_BLOCK_SIZE;
}
static size_t RC2_Decrypt(const char *key, const unsigned char *ciphertext, size_t ctlen, unsigned char *plaintext) {
    RC2_CTX ctx;
    size_t keylen = strlen(key);
    RC2_key_expand(&ctx, (const unsigned char*)key, keylen);
    size_t num_blocks = ctlen / RC2_BLOCK_SIZE;
    for (size_t i = 0; i < num_blocks; ++i) {
        unsigned char block[RC2_BLOCK_SIZE];
        memcpy(block, ciphertext + i*RC2_BLOCK_SIZE, RC2_BLOCK_SIZE);
        RC2_block_decrypt(&ctx, block);
        memcpy(plaintext + i*RC2_BLOCK_SIZE, block, RC2_BLOCK_SIZE);
    }
    return num_blocks * RC2_BLOCK_SIZE;
}

// ========== RC4 ==========
typedef struct {
    uint8_t S[256], i, j;
} RC4_CTX;

static void RC4_set_key(RC4_CTX* ctx, const unsigned char* key, size_t keylen) {
    for (int i = 0; i < 256; ++i)
        ctx->S[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j += ctx->S[i] + key[i % keylen];
        uint8_t tmp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;
    }
    ctx->i = ctx->j = 0;
}
static void RC4_process(RC4_CTX* ctx, unsigned char* data, size_t length) {
    uint8_t i = ctx->i, j = ctx->j;
    for (size_t k = 0; k < length; ++k) {
        i = i + 1;
        j = j + ctx->S[i];
        uint8_t tmp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;
        uint8_t K = ctx->S[(ctx->S[i] + ctx->S[j]) & 0xFF];
        data[k] ^= K;
    }
    ctx->i = i;
    ctx->j = j;
}
static void RC4_Encrypt(const char *key, const char *plaintext, unsigned char *ciphertext) {
    RC4_CTX ctx;
    size_t keylen = strlen(key);
    size_t ptlen = strlen(plaintext);
    RC4_set_key(&ctx, (const unsigned char*)key, keylen);
    memcpy(ciphertext, plaintext, ptlen);
    RC4_process(&ctx, ciphertext, ptlen);
}
static void RC4_Decrypt(const char *key, const unsigned char *ciphertext, size_t ctlen, unsigned char *plaintext) {
    RC4_CTX ctx;
    size_t keylen = strlen(key);
    RC4_set_key(&ctx, (const unsigned char*)key, keylen);
    memcpy(plaintext, ciphertext, ctlen);
    RC4_process(&ctx, plaintext, ctlen);
}

// ========== RC5 ==========
#define RC5_BLOCK_SIZE 8
typedef struct {
    uint32_t S[26];
    uint32_t rounds;
} RC5_CTX;

static uint32_t RC5_rotl(uint32_t x, uint32_t y) { return (x << (y & 31)) | (x >> (32 - (y & 31))); }
static uint32_t RC5_rotr(uint32_t x, uint32_t y) { return (x >> (y & 31)) | (x << (32 - (y & 31))); }
static void RC5_key_expand(RC5_CTX* ctx, const unsigned char* key, size_t keylen, uint32_t rounds) {
    const uint32_t Pw = 0xB7E15163, Qw = 0x9E3779B9;
    size_t Llen = (keylen+3)/4;
    uint32_t* L = (uint32_t*)calloc(Llen ? Llen : 1, sizeof(uint32_t));
    for (int i = keylen-1; i >= 0; --i)
        L[i/4] = (L[i/4] << 8) + key[i];
    ctx->S[0] = Pw;
    for (size_t i = 1; i < 2*rounds+2; ++i)
        ctx->S[i] = ctx->S[i-1] + Qw;
    uint32_t A = 0, B = 0, i = 0, j = 0, v = 3 * (Llen > (2*rounds+2) ? Llen : (2*rounds+2));
    for (uint32_t s = 0; s < v; ++s) {
        A = ctx->S[i] = RC5_rotl(ctx->S[i] + A + B, 3);
        B = L[j] = RC5_rotl(L[j] + A + B, (A+B));
        i = (i+1) % (2*rounds+2);
        j = (j+1) % Llen;
    }
    ctx->rounds = rounds;
    free(L);
}
static void RC5_block_encrypt(const RC5_CTX* ctx, unsigned char* block) {
    uint32_t A, B;
    memcpy(&A, block, 4);
    memcpy(&B, block+4, 4);
    A += ctx->S[0]; B += ctx->S[1];
    for (uint32_t i = 1; i <= ctx->rounds; ++i) {
        A = RC5_rotl(A ^ B, B) + ctx->S[2*i];
        B = RC5_rotl(B ^ A, A) + ctx->S[2*i+1];
    }
    memcpy(block, &A, 4);
    memcpy(block+4, &B, 4);
}
static void RC5_block_decrypt(const RC5_CTX* ctx, unsigned char* block) {
    uint32_t A, B;
    memcpy(&A, block, 4);
    memcpy(&B, block+4, 4);
    for (uint32_t i = ctx->rounds; i >= 1; --i) {
        B = RC5_rotr(B - ctx->S[2*i+1], A) ^ A;
        A = RC5_rotr(A - ctx->S[2*i], B) ^ B;
    }
    B -= ctx->S[1]; A -= ctx->S[0];
    memcpy(block, &A, 4);
    memcpy(block+4, &B, 4);
}
static size_t RC5_Encrypt(const char *key, const char *plaintext, unsigned char *ciphertext, uint32_t rounds) {
    RC5_CTX ctx;
    size_t keylen = strlen(key);
    size_t ptlen = strlen(plaintext);
    RC5_key_expand(&ctx, (const unsigned char*)key, keylen, rounds);
    size_t num_blocks = (ptlen + RC5_BLOCK_SIZE - 1) / RC5_BLOCK_SIZE;
    for (size_t i = 0; i < num_blocks; ++i) {
        unsigned char block[RC5_BLOCK_SIZE] = {0};
        size_t block_len = (ptlen - i*RC5_BLOCK_SIZE > RC5_BLOCK_SIZE) ? RC5_BLOCK_SIZE : (ptlen - i*RC5_BLOCK_SIZE);
        memcpy(block, plaintext + i*RC5_BLOCK_SIZE, block_len);
        RC5_block_encrypt(&ctx, block);
        memcpy(ciphertext + i*RC5_BLOCK_SIZE, block, RC5_BLOCK_SIZE);
    }
    return num_blocks * RC5_BLOCK_SIZE;
}
static size_t RC5_Decrypt(const char *key, const unsigned char *ciphertext, size_t ctlen, unsigned char *plaintext, uint32_t rounds) {
    RC5_CTX ctx;
    size_t keylen = strlen(key);
    RC5_key_expand(&ctx, (const unsigned char*)key, keylen, rounds);
    size_t num_blocks = ctlen / RC5_BLOCK_SIZE;
    for (size_t i = 0; i < num_blocks; ++i) {
        unsigned char block[RC5_BLOCK_SIZE];
        memcpy(block, ciphertext + i*RC5_BLOCK_SIZE, RC5_BLOCK_SIZE);
        RC5_block_decrypt(&ctx, block);
        memcpy(plaintext + i*RC5_BLOCK_SIZE, block, RC5_BLOCK_SIZE);
    }
    return num_blocks * RC5_BLOCK_SIZE;
}

// ========== RC6 ==========
#define RC6_BLOCK_SIZE 16
typedef struct {
    uint32_t S[44];
    uint32_t rounds;
} RC6_CTX;

static uint32_t RC6_rotl(uint32_t x, uint32_t y) { return (x << (y & 31)) | (x >> (32 - (y & 31))); }
static uint32_t RC6_rotr(uint32_t x, uint32_t y) { return (x >> (y & 31)) | (x << (32 - (y & 31))); }
static uint32_t RC6_get_u32(const unsigned char* b) {
    return ((uint32_t)b[0]) | (((uint32_t)b[1]) << 8) | (((uint32_t)b[2]) << 16) | (((uint32_t)b[3]) << 24);
}
static void RC6_set_u32(unsigned char* b, uint32_t v) {
    b[0] = v & 0xFF; b[1] = (v >> 8) & 0xFF; b[2] = (v >> 16) & 0xFF; b[3] = (v >> 24) & 0xFF;
}
static void RC6_key_expand(RC6_CTX* ctx, const unsigned char* key, size_t keylen, uint32_t rounds) {
    const uint32_t Pw = 0xB7E15163, Qw = 0x9E3779B9;
    size_t Llen = (keylen+3)/4;
    uint32_t* L = (uint32_t*)calloc(Llen ? Llen : 1, sizeof(uint32_t));
    for (int i = keylen-1; i >= 0; --i)
        L[i/4] = (L[i/4] << 8) + key[i];
    ctx->S[0] = Pw;
    for (size_t i = 1; i < 44; ++i)
        ctx->S[i] = ctx->S[i-1] + Qw;
    uint32_t A = 0, B = 0, i = 0, j = 0, v = 3*(Llen > 44 ? Llen : 44);
    for (uint32_t s = 0; s < v; ++s) {
        A = ctx->S[i] = RC6_rotl(ctx->S[i] + A + B, 3);
        B = L[j] = RC6_rotl(L[j] + A + B, (A+B));
        i = (i+1) % 44;
        j = (j+1) % Llen;
    }
    ctx->rounds = rounds;
    free(L);
}
static void RC6_block_encrypt(const RC6_CTX* ctx, unsigned char* block) {
    uint32_t A = RC6_get_u32(block);
    uint32_t B = RC6_get_u32(block+4);
    uint32_t C = RC6_get_u32(block+8);
    uint32_t D = RC6_get_u32(block+12);
    B += ctx->S[0];
    D += ctx->S[1];
    for (uint32_t i = 1; i <= ctx->rounds; ++i) {
        uint32_t t = RC6_rotl(B*(2*B+1), 5);
        uint32_t u = RC6_rotl(D*(2*D+1), 5);
        A = RC6_rotl(A^t, u) + ctx->S[2*i];
        C = RC6_rotl(C^u, t) + ctx->S[2*i+1];
        uint32_t tmp = A; A = B; B = C; C = D; D = tmp;
    }
    A += ctx->S[2*ctx->rounds+2];
    C += ctx->S[2*ctx->rounds+3];
    RC6_set_u32(block, A);
    RC6_set_u32(block+4, B);
    RC6_set_u32(block+8, C);
    RC6_set_u32(block+12, D);
}
static void RC6_block_decrypt(const RC6_CTX* ctx, unsigned char* block) {
    uint32_t A = RC6_get_u32(block);
    uint32_t B = RC6_get_u32(block+4);
    uint32_t C = RC6_get_u32(block+8);
    uint32_t D = RC6_get_u32(block+12);
    C -= ctx->S[2*ctx->rounds+3];
    A -= ctx->S[2*ctx->rounds+2];
    for (int i = ctx->rounds; i >= 1; --i) {
        uint32_t tmp = D; D = C; C = B; B = A; A = tmp;
        uint32_t u = RC6_rotl(D*(2*D+1), 5);
        uint32_t t = RC6_rotl(B*(2*B+1), 5);
        C = RC6_rotr(C - ctx->S[2*i+1], t) ^ u;
        A = RC6_rotr(A - ctx->S[2*i], u) ^ t;
    }
    D -= ctx->S[1];
    B -= ctx->S[0];
    RC6_set_u32(block, A);
    RC6_set_u32(block+4, B);
    RC6_set_u32(block+8, C);
    RC6_set_u32(block+12, D);
}
static size_t RC6_Encrypt(const char *key, const char *plaintext, unsigned char *ciphertext, uint32_t rounds) {
    RC6_CTX ctx;
    size_t keylen = strlen(key);
    size_t ptlen = strlen(plaintext);
    RC6_key_expand(&ctx, (const unsigned char*)key, keylen, rounds);
    size_t num_blocks = (ptlen + RC6_BLOCK_SIZE - 1) / RC6_BLOCK_SIZE;
    for (size_t i = 0; i < num_blocks; ++i) {
        unsigned char block[RC6_BLOCK_SIZE] = {0};
        size_t block_len = (ptlen - i*RC6_BLOCK_SIZE > RC6_BLOCK_SIZE) ? RC6_BLOCK_SIZE : (ptlen - i*RC6_BLOCK_SIZE);
        memcpy(block, plaintext + i*RC6_BLOCK_SIZE, block_len);
        RC6_block_encrypt(&ctx, block);
        memcpy(ciphertext + i*RC6_BLOCK_SIZE, block, RC6_BLOCK_SIZE);
    }
    return num_blocks * RC6_BLOCK_SIZE;
}
static size_t RC6_Decrypt(const char *key, const unsigned char *ciphertext, size_t ctlen, unsigned char *plaintext, uint32_t rounds) {
    RC6_CTX ctx;
    size_t keylen = strlen(key);
    RC6_key_expand(&ctx, (const unsigned char*)key, keylen, rounds);
    size_t num_blocks = ctlen / RC6_BLOCK_SIZE;
    for (size_t i = 0; i < num_blocks; ++i) {
        unsigned char block[RC6_BLOCK_SIZE];
        memcpy(block, ciphertext + i*RC6_BLOCK_SIZE, RC6_BLOCK_SIZE);
        RC6_block_decrypt(&ctx, block);
        memcpy(plaintext + i*RC6_BLOCK_SIZE, block, RC6_BLOCK_SIZE);
    }
    return num_blocks * RC6_BLOCK_SIZE;
}

#endif // RC_H
