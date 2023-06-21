//To run the protocol as a Man-in-the-Middle (MITM) attacker and 
//crack the password from A's HMAC-SHA256(K, salt), we've to intercept the communication between
//client or user (C) & server (S) and manipulate the values of b, B, u,salt






#include <iostream>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>

#define SHA256_DIGEST_LENGTH 32

// Calculate the SHA256 hash of the input data
std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);

    std::string result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        result += static_cast<char>(hash[i]);
    }

    return result;
}

// Generate a random 128-bit number
std::string generateRandomNumber() {
    unsigned char buffer[16];
    RAND_bytes(buffer, sizeof(buffer));

    std::string result;
    for (int i = 0; i < 16; i++) {
        result += static_cast<char>(buffer[i]);
    }

    return result;
}

// Perform the attack as the Man-in-the-Middle
void performAttack(const std::string& password) {
    // Arbitrary values chosen by the attacker
    BIGNUM* b = BN_new();
    BIGNUM* B = BN_new();
    BIGNUM* u = BN_new();
    BIGNUM* salt = BN_new();

    BN_set_word(b, 42); // Arbitrary value for b
    BN_set_word(B, 1234); // Arbitrary value for B
    BN_set_word(u, 5678); // Arbitrary value for u
    BN_set_word(salt, 8765); // Arbitrary value for salt

    // Calculate x = SHA256(salt|password)
    std::string saltPassword = BN_bn2hex(salt) + password;
    std::string x = sha256(saltPassword);

    // Calculate S = B^(a + ux) % n
    BIGNUM* S = BN_new();
    BIGNUM* a = BN_new();
    BIGNUM* ux = BN_new();
    BN_set_word(a, 1); // Dummy value for a
    BN_mul(ux, u, b, nullptr);
    BN_add(a, a, ux);
    BN_add(a, a, b);
    BN_mod_exp(S, B, a, nullptr, nullptr);

    // Calculate K = SHA256(S)
    std::string K = sha256(BN_bn2hex(S));

    // Calculate HMAC-SHA256(K, salt)
    std::string hmac = sha256(HMAC(EVP_sha256(), K.c_str(), K.length(), reinterpret_cast<const unsigned char*>(BN_bn2hex(salt)), BN_bn2hex(salt).length(), nullptr, nullptr));

    std::cout << "Cracked password: " << hmac.substr(0, password.length()) << std::endl;

    BN_free(b);
    BN_free(B);
    BN_free(u);
    BN_free(salt);
    BN_free(S);
    BN_free(a);
    BN_free(ux);
}

int main() {
    std::string password = "correct horse battery staple";

    performAttack(password);

    return 0;
}
