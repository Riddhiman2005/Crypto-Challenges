
#include <iostream>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/err.h>

class RSAUtils {
public:
    static RSA* generateKeyPair(int keyLength) {
        RSA* rsaKeyPair = RSA_new();
        BIGNUM* exponent = BN_new();
        BN_set_word(exponent, RSA_F4);
        RSA_generate_key_ex(rsaKeyPair, keyLength, exponent, nullptr);
        BN_free(exponent);
        return rsaKeyPair;
    }

    static std::vector<unsigned char> encrypt(const RSA* publicKey, const std::vector<unsigned char>& plaintext) {
        int maxPlaintextLength = RSA_size(publicKey) - 11;  // RSA_PKCS1_PADDING
        std::vector<unsigned char> ciphertext(RSA_size(publicKey));
        int encryptedBytes = RSA_public_encrypt(static_cast<int>(plaintext.size()), plaintext.data(), ciphertext.data(), publicKey, RSA_PKCS1_PADDING);
        if (encryptedBytes == -1) {
            throw std::runtime_error("Failed to encrypt");
        }
        ciphertext.resize(encryptedBytes);
        return ciphertext;
    }

    static std::vector<unsigned char> decrypt(const RSA* privateKey, const std::vector<unsigned char>& ciphertext) {
        std::vector<unsigned char> plaintext(RSA_size(privateKey));
        int decryptedBytes = RSA_private_decrypt(static_cast<int>(ciphertext.size()), ciphertext.data(), plaintext.data(), privateKey, RSA_PKCS1_PADDING);
        if (decryptedBytes == -1) {
            throw std::runtime_error("Failed to decrypt");
        }
        plaintext.resize(decryptedBytes);
        return plaintext;
    }
};

void challenge39() {
    RSA* publicKey;
    RSA* privateKey;
    publicKey = RSAUtils::generateKeyPair(1024);
    privateKey = RSAPrivateKey_dup(publicKey);  // Copy public key to private key

    std::string msg = "attack at dawn";
    std::vector<unsigned char> plaintext(msg.begin(), msg.end());
    std::vector<unsigned char> ciphertext = RSAUtils::encrypt(publicKey, plaintext);
    std::vector<unsigned char> decrypted = RSAUtils::decrypt(privateKey, ciphertext);

    std::cout << "plaintext: " << msg << std::endl;
    std::cout << "decrypted: " << std::string(decrypted.begin(), decrypted.end()) << std::endl;

    RSA_free(publicKey);
    RSA_free(privateKey);
}

int main() {
    try {
        challenge39();
    } catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }
    return 0;
}
