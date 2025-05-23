#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <array>

// ===== Helper: Hex encode/decode for display =====
inline std::string to_hex(const std::string& data) {
    std::ostringstream oss;
    for (unsigned char c : data)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return oss.str();
}
inline std::string from_hex(const std::string& hex) {
    std::string result;
    for (size_t i = 0; i < hex.length(); i += 2)
        result.push_back((char)std::stoi(hex.substr(i, 2), nullptr, 16));
    return result;
}

// ========== RC2 ==========
class RC2 {
public:
    static constexpr size_t BLOCK_SIZE = 8;
    RC2(const std::string& key) { key_expand(std::vector<uint8_t>(key.begin(), key.end())); }
    std::string encrypt(const std::string& plaintext) const {
        std::string padded = plaintext;
        // Pad with zeros to multiple of BLOCK_SIZE
        size_t pad = (BLOCK_SIZE - (padded.size() % BLOCK_SIZE)) % BLOCK_SIZE;
        padded.append(pad, '\0');
        std::string ciphertext = padded;
        for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE)
            block_encrypt(reinterpret_cast<uint8_t*>(&ciphertext[i]));
        return ciphertext;
    }
    std::string decrypt(const std::string& ciphertext) const {
        if (ciphertext.size() % BLOCK_SIZE != 0)
            throw std::invalid_argument("RC2: ciphertext not multiple of block size");
        std::string plain = ciphertext;
        for (size_t i = 0; i < plain.size(); i += BLOCK_SIZE)
            block_decrypt(reinterpret_cast<uint8_t*>(&plain[i]));
        // Remove trailing zero padding
        while (!plain.empty() && plain.back() == '\0') plain.pop_back();
        return plain;
    }
private:
    std::array<uint16_t, 64> K{};
    void block_encrypt(uint8_t* block) const {
        uint16_t x[4];
        for (int i = 0; i < 4; ++i) x[i] = block[2*i] + (block[2*i+1] << 8);
        int j = 0;
        for (int r = 0; r < 16; ++r) {
            x[0] = (x[0] + ((x[1] & ~x[3]) + (x[2] & x[3]) + K[j++])) & 0xFFFF;
            x[0] = (x[0] << 1) | (x[0] >> 15);
            x[1] = (x[1] + ((x[2] & ~x[0]) + (x[3] & x[0]) + K[j++])) & 0xFFFF;
            x[1] = (x[1] << 2) | (x[1] >> 14);
            x[2] = (x[2] + ((x[3] & ~x[1]) + (x[0] & x[1]) + K[j++])) & 0xFFFF;
            x[2] = (x[2] << 3) | (x[2] >> 13);
            x[3] = (x[3] + ((x[0] & ~x[2]) + (x[1] & x[2]) + K[j++])) & 0xFFFF;
            x[3] = (x[3] << 5) | (x[3] >> 11);
            if (r == 4 || r == 10) for (int i = 0; i < 4; ++i) x[i] = (x[i] + K[x[(i+3)%4] & 63]) & 0xFFFF;
        }
        for (int i = 0; i < 4; ++i) { block[2*i] = x[i] & 0xFF; block[2*i+1] = x[i] >> 8; }
    }
    void block_decrypt(uint8_t* block) const {
        uint16_t x[4];
        for (int i = 0; i < 4; ++i) x[i] = block[2*i] + (block[2*i+1] << 8);
        int j = 63;
        for (int r = 15; r >= 0; --r) {
            if (r == 4 || r == 10) for (int i = 3; i >= 0; --i) x[i] = (x[i] - K[x[(i+3)%4] & 63]) & 0xFFFF;
            x[3] = ((x[3] >> 5) | (x[3] << 11)) & 0xFFFF;
            x[3] = (x[3] - ((x[0] & ~x[2]) + (x[1] & x[2]) + K[j--])) & 0xFFFF;
            x[2] = ((x[2] >> 3) | (x[2] << 13)) & 0xFFFF;
            x[2] = (x[2] - ((x[3] & ~x[1]) + (x[0] & x[1]) + K[j--])) & 0xFFFF;
            x[1] = ((x[1] >> 2) | (x[1] << 14)) & 0xFFFF;
            x[1] = (x[1] - ((x[2] & ~x[0]) + (x[3] & x[0]) + K[j--])) & 0xFFFF;
            x[0] = ((x[0] >> 1) | (x[0] << 15)) & 0xFFFF;
            x[0] = (x[0] - ((x[1] & ~x[3]) + (x[2] & x[3]) + K[j--])) & 0xFFFF;
        }
        for (int i = 0; i < 4; ++i) { block[2*i] = x[i] & 0xFF; block[2*i+1] = x[i] >> 8; }
    }
    void key_expand(const std::vector<uint8_t>& key) {
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
        size_t T = key.size();
        memcpy(L, key.data(), T);
        for (size_t i = T; i < 128; ++i)
            L[i] = PI_SUBST[(L[i-1] + L[i-T]) & 0xFF];
        for (size_t i = 0; i < 64; ++i)
            K[i] = L[2*i] + (L[2*i+1] << 8);
    }
};

// ========== RC4 ==========
class RC4 {
public:
    RC4(const std::string& key) { set_key(std::vector<uint8_t>(key.begin(), key.end())); }
    std::string encrypt(const std::string& plaintext) { // RC4 encrypt/decrypt are identical
        std::string data = plaintext;
        process(reinterpret_cast<uint8_t*>(&data[0]), data.size());
        return data;
    }
    std::string decrypt(const std::string& ciphertext) { // RC4 encrypt/decrypt are identical
        return encrypt(ciphertext);
    }
private:
    void set_key(const std::vector<uint8_t>& key) {
        if (key.empty() || key.size() > 256)
            throw std::invalid_argument("RC4 key size must be 1-256 bytes");
        for (int i = 0; i < 256; ++i) S[i] = static_cast<uint8_t>(i);
        uint8_t j = 0;
        for (int i = 0; i < 256; ++i) {
            j += S[i] + key[i % key.size()];
            std::swap(S[i], S[j]);
        }
        i_ = j_ = 0;
    }
    void process(uint8_t* data, size_t length) {
        uint8_t i = i_, j = j_;
        for (size_t k = 0; k < length; ++k) {
            i = i + 1;
            j = j + S[i];
            std::swap(S[i], S[j]);
            uint8_t K = S[(S[i] + S[j]) & 0xFF];
            data[k] ^= K;
        }
        i_ = i;
        j_ = j;
    }
    uint8_t S[256], i_ = 0, j_ = 0;
};

// ========== RC5 ==========
class RC5 {
public:
    static constexpr size_t BLOCK_SIZE = 8;
    RC5(const std::string& key, uint32_t rounds = 12) : rounds_(rounds) { key_expand(std::vector<uint8_t>(key.begin(), key.end())); }
    std::string encrypt(const std::string& plaintext) const {
        std::string padded = plaintext;
        size_t pad = (BLOCK_SIZE - (padded.size() % BLOCK_SIZE)) % BLOCK_SIZE;
        padded.append(pad, '\0');
        std::string ciphertext = padded;
        for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE)
            block_encrypt(reinterpret_cast<uint8_t*>(&ciphertext[i]));
        return ciphertext;
    }
    std::string decrypt(const std::string& ciphertext) const {
        if (ciphertext.size() % BLOCK_SIZE != 0)
            throw std::invalid_argument("RC5: ciphertext not multiple of block size");
        std::string plain = ciphertext;
        for (size_t i = 0; i < plain.size(); i += BLOCK_SIZE)
            block_decrypt(reinterpret_cast<uint8_t*>(&plain[i]));
        // Remove trailing zero padding
        while (!plain.empty() && plain.back() == '\0') plain.pop_back();
        return plain;
    }
private:
    std::array<uint32_t, 26> S{};
    uint32_t rounds_;
    void block_encrypt(uint8_t* block) const {
        uint32_t A = *(uint32_t*)block, B = *(uint32_t*)(block + 4);
        A += S[0]; B += S[1];
        for (uint32_t i = 1; i <= rounds_; ++i) {
            A = rotl(A ^ B, B) + S[2*i];
            B = rotl(B ^ A, A) + S[2*i+1];
        }
        *(uint32_t*)block = A; *(uint32_t*)(block+4) = B;
    }
    void block_decrypt(uint8_t* block) const {
        uint32_t A = *(uint32_t*)block, B = *(uint32_t*)(block + 4);
        for (uint32_t i = rounds_; i >= 1; --i) {
            B = rotr(B - S[2*i+1], A) ^ A;
            A = rotr(A - S[2*i], B) ^ B;
        }
        B -= S[1]; A -= S[0];
        *(uint32_t*)block = A; *(uint32_t*)(block+4) = B;
    }
    static uint32_t rotl(uint32_t x, uint32_t y) { return (x << (y & 31)) | (x >> (32 - (y & 31))); }
    static uint32_t rotr(uint32_t x, uint32_t y) { return (x >> (y & 31)) | (x << (32 - (y & 31))); }
    void key_expand(const std::vector<uint8_t>& key) {
        constexpr uint32_t Pw = 0xB7E15163, Qw = 0x9E3779B9;
        std::vector<uint32_t> L((key.size()+3)/4, 0);
        for (int i = key.size()-1; i >= 0; --i) L[i/4] = (L[i/4] << 8) + key[i];
        S[0] = Pw;
        for (size_t i = 1; i < 2*rounds_+2; ++i) S[i] = S[i-1] + Qw;
        uint32_t A = 0, B = 0, i = 0, j = 0, v = 3 * std::max((int)L.size(), (int)(2*rounds_+2));
        for (uint32_t s = 0; s < v; ++s) {
            A = S[i] = rotl(S[i] + A + B, 3);
            B = L[j] = rotl(L[j] + A + B, (A+B));
            i = (i+1) % (2*rounds_+2);
            j = (j+1) % L.size();
        }
    }
};

// ========== RC6 ==========
class RC6 {
public:
    static constexpr size_t BLOCK_SIZE = 16;
    RC6(const std::string& key, uint32_t rounds = 20) : rounds_(rounds) { key_expand(std::vector<uint8_t>(key.begin(), key.end())); }
    std::string encrypt(const std::string& plaintext) const {
        std::string padded = plaintext;
        size_t pad = (BLOCK_SIZE - (padded.size() % BLOCK_SIZE)) % BLOCK_SIZE;
        padded.append(pad, '\0');
        std::string ciphertext = padded;
        for (size_t i = 0; i < ciphertext.size(); i += BLOCK_SIZE)
            block_encrypt(reinterpret_cast<uint8_t*>(&ciphertext[i]));
        return ciphertext;
    }
    std::string decrypt(const std::string& ciphertext) const {
        if (ciphertext.size() % BLOCK_SIZE != 0)
            throw std::invalid_argument("RC6: ciphertext not multiple of block size");
        std::string plain = ciphertext;
        for (size_t i = 0; i < plain.size(); i += BLOCK_SIZE)
            block_decrypt(reinterpret_cast<uint8_t*>(&plain[i]));
        // Remove trailing zero padding
        while (!plain.empty() && plain.back() == '\0') plain.pop_back();
        return plain;
    }
private:
    std::array<uint32_t, 44> S{};
    uint32_t rounds_;
    static uint32_t rotl(uint32_t x, uint32_t y) { return (x << (y & 31)) | (x >> (32 - (y & 31))); }
    static uint32_t rotr(uint32_t x, uint32_t y) { return (x >> (y & 31)) | (x << (32 - (y & 31))); }
    static uint32_t get_u32(const uint8_t* b) { return (uint32_t(b[0]) | (uint32_t(b[1]) << 8) | (uint32_t(b[2]) << 16) | (uint32_t(b[3]) << 24)); }
    static void set_u32(uint8_t* b, uint32_t v) {
        b[0] = v & 0xFF; b[1] = (v >> 8) & 0xFF; b[2] = (v >> 16) & 0xFF; b[3] = (v >> 24) & 0xFF;
    }
    void block_encrypt(uint8_t* block) const {
        uint32_t A = get_u32(block), B = get_u32(block+4), C = get_u32(block+8), D = get_u32(block+12);
        B += S[0]; D += S[1];
        for (uint32_t i = 1; i <= rounds_; ++i) {
            uint32_t t = rotl(B*(2*B+1), 5);
            uint32_t u = rotl(D*(2*D+1), 5);
            A = rotl(A^t, u) + S[2*i];
            C = rotl(C^u, t) + S[2*i+1];
            uint32_t tmp = A; A = B; B = C; C = D; D = tmp;
        }
        A += S[2*rounds_+2]; C += S[2*rounds_+3];
        set_u32(block, A); set_u32(block+4, B); set_u32(block+8, C); set_u32(block+12, D);
    }
    void block_decrypt(uint8_t* block) const {
        uint32_t A = get_u32(block), B = get_u32(block+4), C = get_u32(block+8), D = get_u32(block+12);
        C -= S[2*rounds_+3]; A -= S[2*rounds_+2];
        for (int i = rounds_; i >= 1; --i) {
            uint32_t tmp = D; D = C; C = B; B = A; A = tmp;
            uint32_t u = rotl(D*(2*D+1), 5);
            uint32_t t = rotl(B*(2*B+1), 5);
            C = rotr(C - S[2*i+1], t) ^ u;
            A = rotr(A - S[2*i], u) ^ t;
        }
        D -= S[1]; B -= S[0];
        set_u32(block, A); set_u32(block+4, B); set_u32(block+8, C); set_u32(block+12, D);
    }
    void key_expand(const std::vector<uint8_t>& key) {
        constexpr uint32_t Pw = 0xB7E15163, Qw = 0x9E3779B9;
        std::vector<uint32_t> L((key.size()+3)/4, 0);
        for (int i = key.size()-1; i >= 0; --i) L[i/4] = (L[i/4] << 8) + key[i];
        S[0] = Pw;
        for (size_t i = 1; i < 44; ++i) S[i] = S[i-1] + Qw;
        uint32_t A = 0, B = 0, i = 0, j = 0, v = 3*std::max((int)L.size(), 44);
        for (uint32_t s = 0; s < v; ++s) {
            A = S[i] = rotl(S[i] + A + B, 3);
            B = L[j] = rotl(L[j] + A + B, (A+B));
            i = (i+1) % 44;
            j = (j+1) % L.size();
        }
    }
};
