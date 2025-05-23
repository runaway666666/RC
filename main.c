#include "rc.hpp"
#include <iostream>

int main() {
    // RC2
    std::string rc2_key = "rc2key88";
    std::string rc2_plain = "OpenAI!!";
    RC2 rc2(rc2_key);
    std::string rc2_encrypted = rc2.encrypt(rc2_plain);
    std::string rc2_decrypted = rc2.decrypt(rc2_encrypted);
    std::cout << "RC2 encrypted: " << to_hex(rc2_encrypted) << std::endl;
    std::cout << "RC2 decrypted: " << rc2_decrypted << std::endl;

    // RC4 (stream)
    std::string rc4_key = "secretkey";
    std::string rc4_plain = "RC4 is a stream cipher!";
    RC4 rc4(rc4_key);
    std::string rc4_encrypted = rc4.encrypt(rc4_plain);
    std::string rc4_decrypted = rc4.decrypt(rc4_encrypted);
    std::cout << "RC4 encrypted: " << to_hex(rc4_encrypted) << std::endl;
    std::cout << "RC4 decrypted: " << rc4_decrypted << std::endl;

    // RC5
    std::string rc5_key = "rc5key88";
    std::string rc5_plain = "Copilot!";
    RC5 rc5(rc5_key);
    std::string rc5_encrypted = rc5.encrypt(rc5_plain);
    std::string rc5_decrypted = rc5.decrypt(rc5_encrypted);
    std::cout << "RC5 encrypted: " << to_hex(rc5_encrypted) << std::endl;
    std::cout << "RC5 decrypted: " << rc5_decrypted << std::endl;

    // RC6
    std::string rc6_key = "rc6key16bytes!!";
    std::string rc6_plain = "RC6TEST-1234567";
    RC6 rc6(rc6_key);
    std::string rc6_encrypted = rc6.encrypt(rc6_plain);
    std::string rc6_decrypted = rc6.decrypt(rc6_encrypted);
    std::cout << "RC6 encrypted: " << to_hex(rc6_encrypted) << std::endl;
    std::cout << "RC6 decrypted: " << rc6_decrypted << std::endl;

    return 0;
}
