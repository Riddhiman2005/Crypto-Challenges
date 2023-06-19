
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cmath>
#include <random>
#include <cstring>
#include <openssl/aes.h>
#include <iomanip>

constexpr int blockSize = 16;
unsigned char key[blockSize];

void initKeyIV() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < blockSize; ++i) {
        key[i] = static_cast<unsigned char>(dis(gen));
    }
}

bool validPadding(const std::vector<uint8_t>& plainTextPadded) {
    int padding = plainTextPadded.back();
    if (padding > blockSize || padding < 1) {
        return false;
    }
    for (int i = plainTextPadded.size() - 1; i >= plainTextPadded.size() - padding; --i) {
        if (plainTextPadded[i] != padding) {
            return false;
        }
    }
    return true;
}

std::vector<uint8_t> xorBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result(blockSize);
    for (int i = 0; i < blockSize; ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

std::vector<uint8_t> paddingPKCS7(const std::vector<uint8_t>& plainText) {
    int padding = blockSize - (plainText.size() % blockSize);
    std::vector<uint8_t> paddedText = plainText;
    for (int i = 0; i < padding; ++i) {
        paddedText.push_back(padding);
    }
    return paddedText;
}

std::vector<uint8_t> aesCBC_encrypt(const std::vector<uint8_t>& plainTextBase64) {
    std::vector<uint8_t> plainTextUnpadded;
    plainTextUnpadded.reserve(base64_decoded_size(plainTextBase64.size()));
    base64_decode(plainTextBase64.data(), plainTextBase64.size(), plainTextUnpadded.data());

    std::vector<uint8_t> plainText = paddingPKCS7(plainTextUnpadded);
    if (plainText.size() % blockSize != 0) {
        std::cerr << "Padding Error" << std::endl;
        exit(1);
    }

    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, blockSize * 8, &aesKey) < 0) {
        std::cerr << "Cipher Block Error" << std::endl;
        exit(1);
    }

    std::vector<uint8_t> cipherText(plainText.size());
    std::vector<uint8_t> IV(blockSize);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::generate(IV.begin(), IV.end(), [&]() { return static_cast<uint8_t>(dis(gen)); });

    for (int i = 0; i <= plainText.size() - blockSize; i += blockSize) {
        if (i == 0) {
            std::vector<uint8_t> buffer = xorBytes(plainText, IV);
            AES_encrypt(buffer.data(), cipherText.data(), &aesKey);
        } else {
            std::vector<uint8_t> buffer = xorBytes(plainText.data() + i, cipherText.data() + i - blockSize);
            AES_encrypt(buffer.data(), cipherText.data() + i, &aesKey);
        }
    }

    cipherText.insert(cipherText.begin(), IV.begin(), IV.end());

    return cipherText;
}

std::vector<uint8_t> removePadding(const std::vector<uint8_t>& plainTextPadded) {
    int paddingBytes = plainTextPadded.back();
    return std::vector<uint8_t>(plainTextPadded.begin(), plainTextPadded.end() - paddingBytes);
}

bool aesCBC_decrypt(const std::vector<uint8_t>& cipherTextwithIV) {
    std::vector<uint8_t> cipherText(cipherTextwithIV.begin() + blockSize, cipherTextwithIV.end());
    std::vector<uint8_t> IV(cipherTextwithIV.begin(), cipherTextwithIV.begin() + blockSize);
    if (cipherText.size() % blockSize != 0) {
        exit(1);
    }

    AES_KEY aesKey;
    if (AES_set_decrypt_key(key, blockSize * 8, &aesKey) < 0) {
        std::cerr << "Cipher Block Error" << std::endl;
        exit(1);
    }

    std::vector<uint8_t> plainTextPadded(cipherText.size());
    for (int i = 0; i <= cipherText.size() - blockSize; i += blockSize) {
        std::vector<uint8_t> buffer(blockSize);
        if (i == 0) {
            AES_decrypt(cipherText.data() + i, buffer.data(), &aesKey);
            std::vector<uint8_t> temp = xorBytes(IV, buffer);
            std::copy(temp.begin(), temp.end(), plainTextPadded.begin() + i);
        } else {
            AES_decrypt(cipherText.data() + i, buffer.data(), &aesKey);
            std::vector<uint8_t> temp = xorBytes(cipherText.data() + i - blockSize, buffer);
            std::copy(temp.begin(), temp.end(), plainTextPadded.begin() + i);
        }
    }

    return validPadding(plainTextPadded);
}

std::vector<uint8_t> readRandomLine() {
    std::vector<std::string> samples = {
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    };
    int number = rand() % samples.size();
    std::string sample = samples[number];
    return base64Decode(sample);
}

std::vector<uint8_t> paddingOracleAttack(const std::vector<uint8_t>& originalCipherText, const std::vector<uint8_t>& target) {
    std::vector<uint8_t> plainText(blockSize);
    std::vector<uint8_t> priorCipherText(originalCipherText.begin(), originalCipherText.end());
    std::vector<uint8_t> I2(blockSize);
    for (int pos = blockSize - 1; pos >= 0; pos--) {
        int pad_val = blockSize - pos;
        for (int j = blockSize - 1; j > pos; j--) {
            priorCipherText[j] = pad_val ^ I2[j];
        }
        for (int k = 0; k <= 255; k++) {
            priorCipherText[pos] = k;
            std::vector<uint8_t> buffer = concat(priorCipherText, target);
            if (aesCBC_decrypt(buffer)) {
                break;
            }
        }
        I2[pos] = priorCipherText[pos] ^ pad_val;
        plainText[pos] = I2[pos] ^ originalCipherText[pos];
    }
    return plainText;
}

std::vector<uint8_t> paddingOracle(const std::vector<uint8_t>& cipherText) {
    std::vector<uint8_t> plainText(cipherText.size() - blockSize);
    for (int i = cipherText.size() - blockSize; i >= blockSize; i -= blockSize) {
        std::vector<uint8_t> buffer = paddingOracleAttack(std::vector<uint8_t>(cipherText.begin() + i - blockSize, cipherText.begin() + i), std::vector<uint8_t>(cipherText.begin() + i, cipherText.begin() + i + blockSize));
        std::copy(buffer.begin(), buffer.end(), plainText.begin() + i - blockSize);
    }
    return plainText;
}

int main() {
    std::vector<uint8_t> plainTextBase64 = readRandomLine();
    std::vector<uint8_t> cipherText = aesCBC_encrypt(plainTextBase64);
    std::cout << "Ciphertext = " << base64Encode(cipherText) << std::endl;
    std::vector<uint8_t> plainText = paddingOracle(cipherText);
    std::cout << "Plaintext = " << std::string(removePadding(plainText).begin(), removePadding(plainText).end()) << std::endl;
    return 0;
}
