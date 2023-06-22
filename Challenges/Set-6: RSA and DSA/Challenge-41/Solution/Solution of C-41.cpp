
#include <iostream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>

std::string rsaEncrypt(const std::string& plaintext, RSA* publicKey) {
    int maxCipherLen = RSA_size(publicKey);
    std::string ciphertext(maxCipherLen, '\0');
    int cipherLen = RSA_public_encrypt(plaintext.size(), reinterpret_cast<const unsigned char*>(plaintext.data()),
                                       reinterpret_cast<unsigned char*>(ciphertext.data()), publicKey, RSA_PKCS1_PADDING);
    if (cipherLen == -1) {
        std::cerr << "RSA encryption error: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(1);
    }
    ciphertext.resize(cipherLen);
    return ciphertext;
}

std::string rsaDecrypt(const std::string& ciphertext, RSA* privateKey) {
    int maxPlainLen = RSA_size(privateKey);
    std::string plaintext(maxPlainLen, '\0');
    int plainLen = RSA_private_decrypt(ciphertext.size(), reinterpret_cast<const unsigned char*>(ciphertext.data()),
                                       reinterpret_cast<unsigned char*>(plaintext.data()), privateKey, RSA_PKCS1_PADDING);
    if (plainLen == -1) {
        std::cerr << "RSA decryption error: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        exit(1);
    }
    plaintext.resize(plainLen);
    return plaintext;
}

int main() {
    OpenSSL_add_all_algorithms();
    RAND_poll();

    RSA* publicKey = nullptr;
    RSA* privateKey = nullptr;

    // Generate key pair
    privateKey = RSA_new();
    BIGNUM* exponent = BN_new();
    BN_set_word(exponent, RSA_F4);
    RSA_generate_key_ex(privateKey, 1024, exponent, nullptr);

    publicKey = RSAPublicKey_dup(privateKey);

    // Encrypt original message
    std::string originalPlaintext = "s3cr3t sauc3";
    std::string originalCiphertext = rsaEncrypt(originalPlaintext, publicKey);

    // Modify the ciphertext
    BIGNUM* s = BN_new();
    BN_set_word(s, 2);

    BIGNUM* c = BN_bin2bn(reinterpret_cast<const unsigned char*>(originalCiphertext.data()),
                          originalCiphertext.size(), nullptr);

    BIGNUM* c2 = BN_new();
    BN_mod_exp(c2, s, publicKey->e, publicKey->n, nullptr);
    BN_mul(c2, c2, c, publicKey->n, nullptr);

    std::string modifiedCiphertext(BN_num_bytes(c2), '\0');
    BN_bn2bin(c2, reinterpret_cast<unsigned char*>(const_cast<char*>(modifiedCiphertext.data())));

    // Decrypt the modified ciphertext
    std::string decryptedPlaintext = rsaDecrypt(modifiedCiphertext, privateKey);

    BIGNUM* p2 = BN_bin2bn(reinterpret_cast<const unsigned char*>(decryptedPlaintext.data()),
                            decryptedPlaintext.size(), nullptr);

    BIGNUM* p = BN_bin2bn(reinterpret_cast<const unsigned char*>(originalPlaintext.data()),
                          originalPlaintext.size(), nullptr);
    BN_mul(p, p, s, publicKey->n, nullptr);
    BN_mod(p, p, publicKey->n, nullptr);

    BN_mod_inverse(s, s, publicKey->n, nullptr);
    BN_mul(p2, p2, s, publicKey->n, nullptr);

    char* decryptedPlaintextBytes = reinterpret_cast<char*>(malloc(BN_num_bytes(p2)));
    BN_bn2bin(p2, reinterpret_cast<unsigned char*>(decryptedPlaintextBytes));

    std::cout << decryptedPlaintextBytes << std::endl;

    free(decryptedPlaintextBytes);
    RSA_free(publicKey);
    RSA_free(privateKey);
    BN_free(exponent);
    BN_free(s);
    BN_free(c);
    BN_free(c2);
    BN_free(p2);
    BN_free(p);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
