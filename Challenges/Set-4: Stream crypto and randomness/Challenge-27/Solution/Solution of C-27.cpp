
#include <iostream>
#include <openssl/aes.h>
#include <cstring>
#include <random>

const int blockSize = 16;
unsigned char key[blockSize];
unsigned char IV[blockSize];

void initKeyIV() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < blockSize; i++) {
        key[i] = dis(gen);
        IV[i] = key[i];
    }
}

unsigned char* xorBytes(const unsigned char* a, const unsigned char* b, int len) {
    unsigned char* result = new unsigned char[len];
    for (int i = 0; i < len; i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

unsigned char* paddingPKCS7(const unsigned char* plainText, int len, int& paddedLen) {
    int padding = blockSize - (len % blockSize);
    paddedLen = len + padding;
    unsigned char* paddedText = new unsigned char[paddedLen];
    std::memcpy(paddedText, plainText, len);
    for (int i = len; i < paddedLen; i++) {
        paddedText[i] = padding;
    }
    return paddedText;
}

unsigned char* removePadding(const unsigned char* plaintext_padded, int paddedLen, int& len) {
    unsigned char paddingBytes = plaintext_padded[paddedLen - 1];
    len = paddedLen - paddingBytes;
    unsigned char* plainText = new unsigned char[len];
    std::memcpy(plainText, plaintext_padded, len);
    return plainText;
}

unsigned char* aesCBC_encrypt(const unsigned char* plaintext_unpadded, int len) {
    int paddedLen;
    unsigned char* plaintext = paddingPKCS7(plaintext_unpadded, len, paddedLen);
    if (paddedLen % blockSize != 0) {
        std::cout << "Padding Error" << std::endl;
        exit(1);
    }
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);
    unsigned char* cipherText = new unsigned char[paddedLen];

    unsigned char* buffer;
    for (int i = 0; i < paddedLen; i += blockSize) {
        if (i == 0) {
            buffer = xorBytes(plaintext + i, IV, blockSize);
            AES_encrypt(buffer, cipherText + i, &aesKey);
        } else if (i != 0) {
            buffer = xorBytes(plaintext + i, cipherText + i - blockSize, blockSize);
            AES_encrypt(buffer, cipherText + i, &aesKey);
        }
    }

    delete[] plaintext;
    delete[] buffer;
    return cipherText;
}

unsigned char* aesCBC_decrypt(const unsigned char* cipherText, int len, bool& highAscii) {
    if (len % blockSize != 0) {
        std::cout << "Padding Error" << std::endl;
        exit(1);
    }
    AES_KEY aesKey;
    AES_set_decrypt_key(key, 128, &aesKey);
    unsigned char* plainText_padded = new unsigned char[len];
    unsigned char* buffer;
    for (int i = 0; i < len; i += blockSize) {
        buffer = new unsigned char[blockSize];
        if (i == 0) {
            AES_decrypt(cipherText + i, buffer, &aesKey);
            unsigned char* temp = xorBytes(buffer, IV, blockSize);
            std::memcpy(plainText_padded + i, temp, blockSize);
            delete[] temp;
        } else if (i != 0) {
            AES_decrypt(cipherText + i, buffer, &aesKey);
            unsigned char* temp = xorBytes(buffer, cipherText + i - blockSize, blockSize);
            std::memcpy(plainText_padded + i, temp, blockSize);
            delete[] temp;
        }
        delete[] buffer;
    }
    int lenUnpadded;
    unsigned char* plainText = removePadding(plainText_padded, len, lenUnpadded);
    highAscii = false;
    for (int i = 0; i < lenUnpadded; i++) {
        if (plainText[i] > 127) {
            highAscii = true;
            break;
        }
    }
    delete[] plainText_padded;
    return plainText;
}

unsigned char* attacker(const unsigned char* cipherText, int len) {
    unsigned char* cipherText_modified = new unsigned char[len];
    std::memcpy(cipherText_modified, cipherText, len);
    for (int i = 16; i < 32; i++) {
        cipherText_modified[i] = 0;
    }
    std::memcpy(cipherText_modified + 32, cipherText_modified, 16);
    return cipherText_modified;
}

unsigned char* recoverKey(const unsigned char* cipherText_modified, int len) {
    bool err;
    unsigned char* plaintext = aesCBC_decrypt(cipherText_modified, len, err);
    if (err) {
        std::cout << "High ASCII" << std::endl;
    }
    unsigned char* recoveredKey = xorBytes(plaintext, plaintext + 32, blockSize);
    delete[] plaintext;
    return recoveredKey;
}

int main() {
    initKeyIV();
    unsigned char userdata[] = "Ehrsam, Meyer, Smith and Tuchman invented the Cipher Block Chaining (CBC) mode of operation";
    int len = sizeof(userdata) - 1;
    unsigned char* cipherText = aesCBC_encrypt(userdata, len);
    unsigned char* cipherText_modified = attacker(cipherText, len);
    unsigned char* recoveredKey = recoverKey(cipherText_modified, len);

    std::cout << "Recovered Key = ";
    for (int i = 0; i < blockSize; i++) {
        std::cout << std::hex << (int)recoveredKey[i];
    }
    std::cout << std::endl;

    std::cout << "Actual Key    = ";
    for (int i = 0; i < blockSize; i++) {
        std::cout << std::hex << (int)key[i];
    }
    std::cout << std::endl;

    delete[] cipherText;
    delete[] cipherText_modified;
    delete[] recoveredKey;

    return 0;
}

