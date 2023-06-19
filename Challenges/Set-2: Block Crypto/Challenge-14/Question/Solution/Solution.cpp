
#include <iostream>
#include <vector>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cmath>
#include <map>

int blockSize = 16;
std::vector<uint8_t> key, randomBytes;

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> initKey() {
    srand(time(NULL));
    std::vector<uint8_t> key(blockSize);
    RAND_bytes(key.data(), key.size());
    int randLength = rand() % 256;
    std::vector<uint8_t> randomBytes(randLength);
    RAND_bytes(randomBytes.data(), randomBytes.size());
    return std::make_pair(key, randomBytes);
}

std::vector<uint8_t> paddingPKCS7(const std::vector<uint8_t>& plainText) {
    int padding = blockSize - (plainText.size() % blockSize);
    std::vector<uint8_t> paddedText = plainText;
    for (int i = 0; i < padding; i++) {
        paddedText.push_back(padding);
    }
    return paddedText;
}

std::map<std::string, uint8_t> lookupTable(const std::vector<uint8_t>& prefix, int startPos, int number) {
    std::map<std::string, uint8_t> tracker;
    for (int i = 0; i < 128; i++) {
        std::vector<uint8_t> prefixMin(number, 'A');
        std::vector<uint8_t> buffer = prefix;
        buffer.push_back(i);
        std::vector<uint8_t> bufferNew = prefixMin;
        bufferNew.insert(bufferNew.end(), buffer.begin(), buffer.end());
        std::vector<uint8_t> cipherText = aesECBEncrypt(bufferNew);
        tracker[std::string(cipherText.begin() + startPos, cipherText.begin() + startPos + blockSize)] = i;
    }
    return tracker;
}

std::vector<uint8_t> crackECB(const std::vector<uint8_t>& unknownText) {
    std::vector<uint8_t> plainText;
    int number, startPos;
    std::tie(number, startPos) = getStartPos(unknownText);
    for (size_t i = blockSize; i < unknownText.size(); i += blockSize) {
        std::vector<uint8_t> decrypted;
        for (int j = blockSize - 1; j >= 0; j--) {
            std::vector<uint8_t> prefixMin(j, 'A');
            std::vector<uint8_t> prefixNew = prefixMin;
            prefixNew.insert(prefixNew.end(), decrypted.begin(), decrypted.end());
            std::map<std::string, uint8_t> lookup = lookupTable(prefixNew, startPos, number);
            std::vector<uint8_t> buffer = prefixMin;
            buffer.insert(buffer.end(), unknownText.begin() + i - blockSize, unknownText.begin() + i);
            std::vector<uint8_t> prefixBoth = prefixMin;
            prefixBoth.insert(prefixBoth.end(), buffer.begin(), buffer.end());
            std::vector<uint8_t> cipherText = aesECBEncrypt(prefixBoth);
            decrypted.push_back(lookup[std::string(cipherText.begin() + startPos, cipherText.begin() + startPos + blockSize)]);
        }
        plainText.insert(plainText.end(), decrypted.begin(), decrypted.end());
    }
    return plainText;
}

std::vector<uint8_t> aesECBEncrypt(const std::vector<uint8_t>& plainTextNormal) {
    std::vector<uint8_t> plainTextNew = randomBytes;
    plainTextNew.insert(plainTextNew.end(), plainTextNormal.begin(), plainTextNormal.end());
    std::vector<uint8_t> plainText = paddingPKCS7(plainTextNew);
    if (plainText.size() % blockSize != 0) {
        std::cout << "Padding Error" << std::endl;
        exit(1);
    }
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key.data(), 128, &aesKey) < 0) {
        std::cout << "AES Error" << std::endl;
        exit(1);
    }
    std::vector<uint8_t> cipherText(plainText.size());
    for (size_t i = 0; i < plainText.size(); i += blockSize) {
        AES_encrypt(plainText.data() + i, cipherText.data() + i, &aesKey);
    }
    return cipherText;
}

std::pair<int, int> getStartPos(const std::vector<uint8_t>& plainText) {
    for (int i = 0;; i++) {
        std::vector<uint8_t> plainTextNew(i, 'A');
        plainTextNew.insert(plainTextNew.end(), plainText.begin(), plainText.end());
        std::vector<uint8_t> cipherText = aesECBEncrypt(plainTextNew);
        for (size_t j = blockSize; j < cipherText.size() - blockSize; j += blockSize) {
            if (memcmp(cipherText.data() + j - blockSize, cipherText.data() + j, blockSize) == 0) {
                return std::make_pair(i - (2 * blockSize), j - blockSize);
            }
        }
    }
    return std::make_pair(0, 0);
}

int main() {
    std::string unknownStringBase64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    int len = Base64decode_len(unknownStringBase64.c_str());
    std::vector<uint8_t> unknownString(len);
    int unknownStringDecodedLen = Base64decode((char*)unknownString.data(), unknownStringBase64.c_str());
    if (unknownStringDecodedLen != len) {
        std::cout << "Unknown string encoding issue" << std::endl;
        exit(1);
    }
    std::cout << std::string(crackECB(unknownString).begin(), crackECB(unknownString).end()) << std::endl;
    return 0;
}

