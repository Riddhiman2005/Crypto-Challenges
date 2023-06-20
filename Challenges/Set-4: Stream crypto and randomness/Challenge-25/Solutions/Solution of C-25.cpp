
#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

std::vector<unsigned char> key;
int blocksize;

std::vector<unsigned char> initKey() {
    blocksize = 16;
    key.resize(blocksize);
    if (RAND_bytes(key.data(), blocksize) != 1) {
        std::cerr << "Key Issue" << std::endl;
        exit(1);
    }
    return key;
}

std::vector<unsigned char> decrypt(const std::vector<unsigned char>& cipherText, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> plainText(cipherText.size());
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1) {
        std::cerr << "AES error" << std::endl;
        exit(1);
    }
    int outlen;
    if (EVP_DecryptUpdate(ctx, plainText.data(), &outlen, cipherText.data(), cipherText.size()) != 1) {
        std::cerr << "AES error" << std::endl;
        exit(1);
    }
    int tmplen;
    if (EVP_DecryptFinal_ex(ctx, plainText.data() + outlen, &tmplen) != 1) {
        std::cerr << "AES error" << std::endl;
        exit(1);
    }
    EVP_CIPHER_CTX_free(ctx);
    return plainText;
}

std::vector<unsigned char> aesCTR_decrypt(const std::vector<unsigned char>& cipherText) {
    std::vector<unsigned char> plainText;
    int tracker = 0;
    int i;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1) {
        std::cerr << "AES error" << std::endl;
        exit(1);
    }
    int counter = 0;
    int nonce = 0;
    std::vector<unsigned char> nonce_byte(8);
    std::vector<unsigned char> counter_byte(8);
    while (plainText.size() <= cipherText.size()) {
        std::vector<unsigned char> buffer(blocksize);
        memcpy(nonce_byte.data(), &nonce, 8);
        memcpy(counter_byte.data(), &counter, 8);
        if (EVP_EncryptUpdate(ctx, buffer.data(), &i, nonce_byte.data(), 8) != 1) {
            std::cerr << "AES error" << std::endl;
            exit(1);
        }
        if (EVP_EncryptUpdate(ctx, buffer.data() + 8, &i, counter_byte.data(), 8) != 1) {
            std::cerr << "AES error" << std::endl;
            exit(1);
        }
        for (i = 0; i < blocksize; i++) {
            if (tracker == cipherText.size()) {
                EVP_CIPHER_CTX_free(ctx);
                return plainText;
            }
            plainText.push_back(buffer[i] ^ cipherText[tracker]);
            tracker++;
        }
        nonce = 0;
        counter++;
    }
    EVP_CIPHER_CTX_free(ctx);
    return plainText;
}

std::vector<unsigned char> aesCTR_encrypt(const std::vector<unsigned char>& plainText) {
    std::vector<unsigned char> cipherText;
    int tracker = 0;
    int i;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1) {
        std::cerr << "AES error" << std::endl;
        exit(1);
    }
    int counter = 0;
    int nonce = 0;
    std::vector<unsigned char> nonce_byte(8);
    std::vector<unsigned char> counter_byte(8);
    while (cipherText.size() <= plainText.size()) {
        std::vector<unsigned char> buffer(blocksize);
        memcpy(nonce_byte.data(), &nonce, 8);
        memcpy(counter_byte.data(), &counter, 8);
        if (EVP_EncryptUpdate(ctx, buffer.data(), &i, nonce_byte.data(), 8) != 1) {
            std::cerr << "AES error" << std::endl;
            exit(1);
        }
        if (EVP_EncryptUpdate(ctx, buffer.data() + 8, &i, counter_byte.data(), 8) != 1) {
            std::cerr << "AES error" << std::endl;
            exit(1);
        }
        for (i = 0; i < blocksize; i++) {
            if (tracker == plainText.size()) {
                EVP_CIPHER_CTX_free(ctx);
                return cipherText;
            }
            cipherText.push_back(buffer[i] ^ plainText[tracker]);
            tracker++;
        }
        nonce = 0;
        counter++;
    }
    EVP_CIPHER_CTX_free(ctx);
    return cipherText;
}

std::vector<unsigned char> edit(const std::vector<unsigned char>& cipherText, unsigned char newText, int offset) {
    std::vector<unsigned char> plainText = aesCTR_decrypt(cipherText);
    plainText[offset] = newText;
    return aesCTR_encrypt(plainText);
}

std::vector<unsigned char> aesBruteforce(const std::vector<unsigned char>& cipherText) {
    std::vector<unsigned char> plainText(cipherText.size());
    for (int i = 0; i < cipherText.size(); i++) {
        for (int j = 0; j < 256; j++) {
            std::vector<unsigned char> newCipherText = edit(cipherText, static_cast<unsigned char>(j), i);
            if (newCipherText[i] == cipherText[i]) {
                plainText[i] = static_cast<unsigned char>(j);
                break;
            }
        }
    }
    return plainText;
}

int main() {
    std::string filename = "Data.txt";
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Input File Error" << std::endl;
        exit(1);
    }
    std::string filecontent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::vector<unsigned char> ciphertext;
    try {
        ciphertext = base64Decode(filecontent);
    } catch (const std::exception& e) {
        std::cerr << "Base64 Decoding Error: " << e.what() << std::endl;
        exit(1);
    }
    if (ciphertext.size() % blocksize != 0) {
        std::cerr << "File Size Error" << std::endl;
        exit(1);
    }
    std::vector<unsigned char> plainText = decrypt(ciphertext, std::vector<unsigned char>("YELLOW SUBMARINE", "YELLOW SUBMARINE" + 16));
    std::vector<unsigned char> cipherText_aesctr = aesCTR_encrypt(plainText);
    std::vector<unsigned char> plainText_recovered = aesBruteforce(cipherText_aesctr);
    std::cout << std::string(plainText_recovered.begin(), plainText_recovered.end()) << std::endl;
    return 0;
}

