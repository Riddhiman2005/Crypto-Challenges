
#include <iostream>
#include <vector>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

std::vector<uint8_t> xorBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

std::vector<uint8_t> aesCBC(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key) {
    int blocksize = 16;
    if (plaintext.size() % blocksize != 0) {
        std::cout << "Padding Error" << std::endl;
        exit(1);
    }
    std::vector<uint8_t> cipherText(plaintext.size());
    AES_KEY aesKey;
    AES_set_encrypt_key(key.data(), 128, &aesKey);

    std::vector<uint8_t> iv(blocksize);
    RAND_bytes(iv.data(), blocksize);

    for (size_t i = 0; i < plaintext.size(); i += blocksize) {
        if (i == 0) {
            std::vector<uint8_t> buffer = xorBytes(plaintext.data() + i, iv);
            AES_encrypt(buffer.data(), cipherText.data() + i, &aesKey);
        } else {
            std::vector<uint8_t> buffer = xorBytes(plaintext.data() + i, cipherText.data() + i - blocksize);
            AES_encrypt(buffer.data(), cipherText.data() + i, &aesKey);
        }
    }
    return cipherText;
}

std::vector<uint8_t> aesECB(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key) {
    int blocksize = 16;
    if (plaintext.size() % blocksize != 0) {
        std::cout << "Padding Error" << std::endl;
        exit(1);
    }
    std::vector<uint8_t> cipherText(plaintext.size());
    AES_KEY aesKey;
    AES_set_encrypt_key(key.data(), 128, &aesKey);

    for (size_t i = 0; i < plaintext.size(); i += blocksize) {
        AES_encrypt(plaintext.data() + i, cipherText.data() + i, &aesKey);
    }
    return cipherText;
}

std::vector<uint8_t> randomData(const std::vector<uint8_t>& plaintext) {
    int p = 0;
    int max = 3;
    srand(time(NULL));
    while (p == 0) {
        p = rand() % max;
    }

    std::vector<uint8_t> buffer(p);
    RAND_bytes(buffer.data(), p);

    std::string bufferStr(buffer.begin(), buffer.end());
    std::string plaintextPadded = bufferStr + std::string(plaintext.begin(), plaintext.end()) + bufferStr;
    std::vector<uint8_t> plaintextPaddedVec(plaintextPadded.begin(), plaintextPadded.end());
    return plaintextPaddedVec;
}

std::vector<uint8_t> paddingPKCS7(const std::vector<uint8_t>& plainText, int blockSize) {
    int padding = blockSize - (plainText.size() % blockSize);
    std::vector<uint8_t> paddedText = plainText;
    for (int i = 0; i < padding; i++) {
        paddedText.push_back(padding);
    }
    return paddedText;
}

bool detectECB(const std::vector<uint8_t>& cipherText) {
    std::map<std::string, int> tracker;
    bool init = false;
    for (size_t i = 16; i <= cipherText.size(); i++) {
        if (!init) {
            std::string block(cipherText.begin() + i - 16, cipherText.begin() + i);
            tracker[block] = 1;
            init = true;
        } else {
            std::string block(cipherText.begin() + i - 16, cipherText.begin() + i);
            if (tracker.find(block) != tracker.end()) {
                return true;
            } else {
                tracker[block] = 1;
            }
        }
    }
    return false;
}

int main() {
    srand(time(NULL));
    int p = 0;
    int max = 3;
    while (p == 0) {
        p = rand() % max;
    }

    std::vector<uint8_t> key(16);
    RAND_bytes(key.data(), key.size());

    std::string plaintext = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    if (p == 1) {
        std::cout << "Selected mode: CBC" << std::endl;
        std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());
        std::vector<uint8_t> plaintextPadded = randomData(plaintextVec);
        std::vector<uint8_t> cipherText = aesCBC(paddingPKCS7(plaintextPadded, 16), key);
        if (!detectECB(cipherText)) {
            std::cout << "Detected Mode: CBC" << std::endl;
        }
    } else if (p == 2) {
        std::cout << "Selected mode: ECB" << std::endl;
        std::vector<uint8_t> plaintextVec(plaintext.begin(), plaintext.end());
        std::vector<uint8_t> plaintextPadded = randomData(plaintextVec);
        std::vector<uint8_t> cipherText = aesECB(paddingPKCS7(plaintextPadded, 16), key);
        if (detectECB(cipherText)) {
            std::cout << "Detected Mode: ECB" << std::endl;
        }
    }

    return 0;
}

