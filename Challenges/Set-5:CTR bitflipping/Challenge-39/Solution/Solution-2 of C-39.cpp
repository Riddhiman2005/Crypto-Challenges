#include <iostream>
#include <openssl/bn.h>

// Function to compute the modular multiplicative inverse (invmod)

// Returns -1 if the inverse doesn't exist

BIGNUM* invmod(const BIGNUM* a, const BIGNUM* n) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* result = BN_new();
    if (BN_mod_inverse(result, a, n, ctx) == nullptr) {
        BN_free(result);
        result = nullptr;
    }
    BN_CTX_free(ctx);
    return result;
}

// Function to perform RSA encryption
BIGNUM* encrypt(const BIGNUM* message, const BIGNUM* e, const BIGNUM* n) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* ciphertext = BN_new();
    BN_mod_exp(ciphertext, message, e, n, ctx);
    BN_CTX_free(ctx);
    return ciphertext;
}

// Function to perform RSA decryption
BIGNUM* decrypt(const BIGNUM* ciphertext, const BIGNUM* d, const BIGNUM* n) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* plaintext = BN_new();
    BN_mod_exp(plaintext, ciphertext, d, n, ctx);
    BN_CTX_free(ctx);
    return plaintext;
}

int main() {
    // Generate small prime numbers p and q
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BN_dec2bn(&p, "13");
    BN_dec2bn(&q, "17");

    // Compute n = p * q
    BIGNUM* n = BN_new();
    BN_mul(n, p, q, nullptr);

    // Compute et = (p-1) * (q-1)
    BIGNUM* et = BN_new();
    BIGNUM* p_minus_one = BN_new();
    BIGNUM* q_minus_one = BN_new();
    BN_sub(p_minus_one, p, BN_value_one());
    BN_sub(q_minus_one, q, BN_value_one());
    BN_mul(et, p_minus_one, q_minus_one, nullptr);

    // Choose e = 3
    BIGNUM* e = BN_new();
    BN_set_word(e, 3);

    // Compute d = invmod(e, et)
    BIGNUM* d = invmod(e, et);
    if (d == nullptr) {
        std::cerr << "Failed to compute modular inverse" << std::endl;
        return 1;
    }

    // Test encryption and decryption with a number (42)
    BIGNUM* message = BN_new();
    BN_dec2bn(&message, "42");
    BIGNUM* ciphertext = encrypt(message, e, n);
    BIGNUM* decrypted = decrypt(ciphertext, d, n);

    // Print the results
    char* plaintext_hex = BN_bn2hex(message);
    char* ciphertext_hex = BN_bn2hex(ciphertext);
    char* decrypted_hex = BN_bn2hex(decrypted);
    std::cout << "Plaintext: " << plaintext_hex << std::endl;
    std::cout << "Ciphertext: " << ciphertext_hex << std::endl;
    std::cout << "Decrypted: " << decrypted_hex << std::endl;

    // Free the resources
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(et);
    BN_free(p_minus_one);
    BN_free(q_minus_one);
    BN_free(e);
    BN_free(d);
    BN_free(message);
    BN_free(ciphertext);
    BN_free(decrypted);
    OPENSSL_free(plaintext_hex);
    OPENSSL_free(ciphertext_hex);
    OPENSSL_free(decrypted_hex);

    return 0;
}
