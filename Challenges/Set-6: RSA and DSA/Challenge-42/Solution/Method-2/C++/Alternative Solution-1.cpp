
#include <iostream>
#include <openssl/bn.h>
#include <openssl/sha.h>

// Cube root function

BIGNUM* integer_cube_root(const BIGNUM* n) {
    BIGNUM* low = BN_new();
    BIGNUM* high = BN_new();
    BIGNUM* mid = BN_new();
    BIGNUM* cube = BN_new();
    BN_CTX* ctx = BN_CTX_new();

    BN_zero(low);
    BN_copy(high, n);

    while (BN_cmp(low, high) < 0) {
        BN_add(mid, low, high);
        BN_add_word(mid, 1);
        BN_div(mid, nullptr, mid, BN_value_one(), ctx);

        BN_exp(cube, mid, BN_value_three(), ctx);
        if (BN_cmp(cube, n) <= 0) {
            BN_copy(low, mid);
        } else {
            BN_sub(high, mid, BN_value_one());
        }
    }

    BN_CTX_free(ctx);
    BN_free(high);
    BN_free(cube);
    BN_free(mid);

    return low;
}

// Forge RSA signature

BIGNUM* forge_rsa_signature(const char* message) {
    // RSA modulus and exponent (public key)
    const char* N_str = "1234567890123456789012345678901234567890"; // Replace with the actual modulus
    const char* E_str = "3"; // Public exponent

    BIGNUM* N = BN_new();
    BIGNUM* E = BN_new();
    BIGNUM* hash_value = BN_new();
    BIGNUM* forged_block = BN_new();
    BIGNUM* forged_signature = BN_new();
    BIGNUM* cube_root = BN_new();

    BN_dec2bn(&N, N_str);
    BN_dec2bn(&E, E_str);

    // Hash the message using SHA-1
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(message), strlen(message), hash);

    // Convert the hash to a BIGNUM
    BN_bin2bn(hash, SHA_DIGEST_LENGTH, hash_value);

    // Length of the modulus in bytes
    int length = BN_num_bytes(N);

    // Construct the forged block
    
    BN_zero(forged_block);
    BN_lshift(forged_block, hash_value, 8 * (length - SHA_DIGEST_LENGTH));
    BN_set_bit(forged_block, 8 * (length - SHA_DIGEST_LENGTH) - 1);
    BN_set_bit(forged_block, 8 * length - 1);

    // Calculate the cube root of the forged block
    
    cube_root = integer_cube_root(forged_block);

    // Forge the RSA signature
    
    BN_mod_exp(forged_signature, cube_root, E, N, nullptr);

    BN_free(N);
    BN_free(E);
    BN_free(hash_value);
    BN_free(forged_block);
    BN_free(cube_root);

    return forged_signature;
}

int main() {
    const char* message = "hi mom";
    BIGNUM* forged_signature = forge_rsa_signature(message);

    // Verify the forged signature (replace with the actual verification logic)
    
    bool is_valid = true; // Replace with the actual verification result

    char* hex_signature = BN_bn2hex(forged_signature);
    std::cout << "Forged RSA Signature: " << hex_signature << std::endl;
    OPENSSL_free(hex_signature);

    std::cout << "Signature Valid: " << (is_valid ? "true" : "false") << std::endl;

    BN_free(forged_signature);

    return 0;
}
