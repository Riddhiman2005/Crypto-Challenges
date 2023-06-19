
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstring>
#include <random>
#include <algorithm>
#include <cmath>
#include <cassert>
#include <openssl/aes.h>

const int blockSize = 16;

std::vector<uint8_t> key(blockSize);
std::vector<uint8_t> IV(blockSize);

void initKeyIV() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> distrib(0, 255);

    for (int i = 0; i < blockSize; i++) {
        key[i] = distrib(gen);
        IV[i] = distrib(gen);
    }
}

std::vector<uint8_t> xorBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    assert(a.size() == b.size());

    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

std::vector<uint8_t> paddingPKCS7(const std::vector<uint8_t>& plainText) {
    int padding = blockSize - (plainText.size() % blockSize);
    std::vector<uint8_t> paddedText = plainText;
    for (int i = 0; i < padding; i++) {
        paddedText.push_back(padding);
    }
    return paddedText;
}

std::vector<uint8_t> removePadding(const std::vector<uint8_t>& plaintextPadded) {
    int paddingBytes = plaintextPadded[plaintextPadded.size() - 1];
    std::vector<uint8_t> plainText(plaintextPadded.begin(), plaintextPadded.end() - paddingBytes);
    return plainText;
}

std::vector<uint8_t> aesCBC_encrypt(const std::vector<uint8_t>& plaintextUnpadded) {
    std::vector<uint8_t> plaintext = paddingPKCS7(plaintextUnpadded);
    assert(plaintext.size() % blockSize == 0);

    AES_KEY aesKey;
    AES_set_encrypt_key(key.data(), 128, &aesKey);

    std::vector<uint8_t> cipherText(plaintext.size());

    std::vector<uint8_t> prevCipherBlock = IV;
    for (size_t i = 0; i < plaintext.size(); i += blockSize) {
        std::vector<uint8_t> buffer = xorBytes(plaintext.data() + i, prevCipherBlock.data());
        AES_encrypt(buffer.data(), cipherText.data() + i, &aesKey);
        prevCipherBlock = cipherText;
    }
    return cipherText;
}

std::vector<uint8_t> aesCBC_decrypt(const std::vector<uint8_t>& cipherText) {
    assert(cipherText.size() % blockSize == 0);

    AES_KEY aesKey;
    AES_set_decrypt_key(key.data(), 128, &aesKey);

    std::vector<uint8_t> plainTextPadded(cipherText.size());

    std::vector<uint8_t> prevCipherBlock = IV;
    for (size_t i = 0; i < cipherText.size(); i += blockSize) {
        std::vector<uint8_t> buffer(blockSize);
        AES_decrypt(cipherText.data() + i, buffer.data(), &aesKey);
        std::vector<uint8_t> plainBlock = xorBytes(buffer, prevCipherBlock);
        std::copy(plainBlock.begin(), plainBlock.end(), plainTextPadded.begin() + i);
        prevCipherBlock = cipherText.data() + i;
    }

    std::vector<uint8_t> plainText = removePadding(plainTextPadded);
    return plainText;
}

std::vector<uint8_t> prependData(const std::vector<uint8_t>& plaintext) {
    std::string data = "comment1=cooking%20MCs;userdata=";
    std::vector<uint8_t> prependedText(data.begin(), data.end());
    prependedText.insert(prependedText.end(), plaintext.begin(), plaintext.end());
    return prependedText;
}

std::vector<uint8_t> quoteOut(const std::vector<uint8_t>& plainText) {
    std::string buffer(plainText.begin(), plainText.end());
    std::replace(buffer.begin(), buffer.end(), ';', '?');
    std::replace(buffer.begin(), buffer.end(), '=', '?');
    return std::vector<uint8_t>(buffer.begin(), buffer.end());
}

std::vector<uint8_t> appendData(const std::vector<uint8_t>& plaintext) {
    std::string data = ";comment2=%20like%20a%20pound%20of%20bacon";
    std::vector<uint8_t> appendedText(plaintext.begin(), plaintext.end());
    appendedText.insert(appendedText.end(), data.begin(), data.end());
    return appendedText;
}

std::vector<uint8_t> getModifiedCipherText(const std::vector<uint8_t>& cipherText, const std::vector<uint8_t>& plainText) {
    std::vector<uint8_t> beforeXorPlaintext(plainText.begin() + 32, plainText.begin() + 48);
    std::vector<uint8_t> cipherTextBlock(cipherText.begin() + 16, cipherText.begin() + 32);
    cipherTextBlock[0] ^= beforeXorPlaintext[0] ^ ';';
    cipherTextBlock[11] ^= beforeXorPlaintext[11] ^ ';';
    cipherTextBlock[6] ^= beforeXorPlaintext[6] ^ '=';
    std::copy(cipherTextBlock.begin(), cipherTextBlock.end(), cipherText.begin() + 16);
    return cipherText;
}

bool attackSuccess(const std::vector<uint8_t>& cipherText) {
    std::vector<uint8_t> cipherTextNew = getModifiedCipherText(cipherText, aesCBC_decrypt(cipherText));
    std::vector<uint8_t> plainTextNew = aesCBC_decrypt(cipherTextNew);
    std::string plaintextStr(plainTextNew.begin(), plainTextNew.end());
    return plaintextStr.find(";admin=true;") != std::string::npos;
}

int main() {
    initKeyIV();

    std::string userData = ";admin=true;";
    std::vector<uint8_t> plaintext(userData.begin(), userData.end());
    plaintext = prependData(plaintext);
    plaintext = appendData(plaintext);
    plaintext = quoteOut(plaintext);

    std::vector<uint8_t> cipherText = aesCBC_encrypt(plaintext);
    std::cout << "CipherText: ";
    for (const auto& byte : cipherText) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;

    if (attackSuccess(cipherText)) {
        std::cout << "Attack Success" << std::endl;
    } else {
        std::cout << "Bad Attack" << std::endl;
    }

    return 0;
}
