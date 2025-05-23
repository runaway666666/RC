#include <stdio.h>
#include <string.h>
#include "rc.h"

void print_hex(const char* label, const unsigned char* data, size_t len) {
    char hex[2*len+1];
    to_hex(data, len, hex);
    printf("%s: %s\n", label, hex);
}

int main() {
    unsigned char ciphertext[256], decrypted[256];
    size_t enclen, declen;

    // RC2 DEMO
    printf("===== RC2 DEMO =====\n");
    const char* rc2_key = "myrc2key";
    const char* rc2_plain = "RC2block";
    enclen = RC2_Encrypt(rc2_key, rc2_plain, ciphertext);
    print_hex("RC2 Ciphertext", ciphertext, enclen);
    declen = RC2_Decrypt(rc2_key, ciphertext, enclen, decrypted);
    printf("RC2 Decrypted: %.*s\n\n", (int)declen, decrypted);

    // RC4 DEMO
    printf("===== RC4 DEMO =====\n");
    const char* rc4_key = "myrc4key";
    const char* rc4_plain = "Arbitrary RC4 data!";
    size_t rc4_len = strlen(rc4_plain);
    RC4_Encrypt(rc4_key, rc4_plain, ciphertext);
    print_hex("RC4 Ciphertext", ciphertext, rc4_len);
    RC4_Decrypt(rc4_key, ciphertext, rc4_len, decrypted);
    decrypted[rc4_len] = '\0'; // Null-terminate for print
    printf("RC4 Decrypted: %s\n\n", decrypted);

    // RC5 DEMO
    printf("===== RC5 DEMO =====\n");
    const char* rc5_key = "myrc5key";
    const char* rc5_plain = "RC5block";
    enclen = RC5_Encrypt(rc5_key, rc5_plain, ciphertext, 12);
    print_hex("RC5 Ciphertext", ciphertext, enclen);
    declen = RC5_Decrypt(rc5_key, ciphertext, enclen, decrypted, 12);
    printf("RC5 Decrypted: %.*s\n\n", (int)declen, decrypted);

    // RC6 DEMO
    printf("===== RC6 DEMO =====\n");
    const char* rc6_key = "myrc6key";
    const char* rc6_plain = "RC6_BLOCK_DATA!!";
    enclen = RC6_Encrypt(rc6_key, rc6_plain, ciphertext, 20);
    print_hex("RC6 Ciphertext", ciphertext, enclen);
    declen = RC6_Decrypt(rc6_key, ciphertext, enclen, decrypted, 20);
    printf("RC6 Decrypted: %.*s\n", (int)declen, decrypted);

    return 0;
}
