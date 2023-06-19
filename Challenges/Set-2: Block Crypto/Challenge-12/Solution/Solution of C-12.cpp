
#include <iostream>
#include <vector>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cmath>
#include <map>

int blocksize;
std::vector<uint8_t> key;

std::vector<uint8_t> initKey() {
    srand(time(NULL));
    blocksize = 16;
    std::vector<uint8_t> key(blocksize);
    RAND_bytes(key.data(), key.size());
    return key;
}

std::vector<uint8_t> aesECB(const std::vector<uint8_t>& plaintext) {
    if (plaintext.size() % blocksize != 0) {
        std::cout << "Padding Error" << std::endl;
        exit(1);
    }
    AES_KEY aesKey;
    AES_set_encrypt_key(key.data(), 128, &aesKey);
    std::vector<uint8_t> cipherText(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); i += blocksize) {
        AES_encrypt(plaintext.data() + i, cipherText.data() + i, &aesKey);
    }
    return cipherText;
}

std::vector<uint8_t> paddingPKCS7(const std::vector<uint8_t>& plainText) {
    int padding = blocksize - (plainText.size() % blocksize);
    std::vector<uint8_t> paddedText = plainText;
    for (int i = 0; i < padding; i++) {
        paddedText.push_back(padding);
    }
    return paddedText;
}

int guessBlockSize(const std::string& unknown) {
    std::string plaintext = "A";
    int length = 0;
    bool init = false;
    std::string buffer;
    while (true) {
        if (!init) {
            buffer = plaintext + unknown;
            std::vector<uint8_t> plaintextPadded = paddingPKCS7(std::vector<uint8_t>(buffer.begin(), buffer.end()));
            std::vector<uint8_t> cipherText = aesECB(plaintextPadded);
            length = cipherText.size();
            init = true;
        } else if (init) {
            buffer = plaintext + buffer;
            std::vector<uint8_t> plaintextPadded = paddingPKCS7(std::vector<uint8_t>(buffer.begin(), buffer.end()));
            std::vector<uint8_t> cipherText = aesECB(plaintextPadded);
            int lengthNew = cipherText.size();
            if (lengthNew > length) {
                return lengthNew - length;
            }
        }
    }
    return length;
}

std::map<std::string, uint8_t> lookupTable(const std::vector<uint8_t>& prefix) {
    std::map<std::string, uint8_t> tracker;
    for (uint8_t i = 0; i < 128; i++) {
        std::vector<uint8_t> buffer = prefix;
        buffer.push_back(i);
        std::vector<uint8_t> bufferPadded = paddingPKCS7(buffer);
        std::vector<uint8_t> cipherText = aesECB(bufferPadded);
        tracker[std::string(cipherText.begin(), cipherText.begin() + blocksize)] = i;
    }
    return tracker;
}

std::vector<uint8_t> crackECB(const std::vector<uint8_t>& unknownText, int blocksize) {
    std::vector<uint8_t> plainText;
    for (size_t i = blocksize; i < unknownText.size(); i += blocksize) {
        std::vector<uint8_t> decrypted;
        for (int j = blocksize - 1; j >= 0; j--) {
            std::vector<uint8_t> prefix(j, 'A');
            prefix.insert(prefix.end(), decrypted.begin(), decrypted.end());
            std::map<std::string, uint8_t> lookup = lookupTable(prefix);
            std::vector<uint8_t> buffer = prefix;
            buffer.insert(buffer.end(), unknownText.begin() + i - blocksize, unknownText.begin() + i);
            std::vector<uint8_t> plainTextPadded = paddingPKCS7(buffer);
            std::vector<uint8_t> cipherText = aesECB(plainTextPadded);
            std::string block(cipherText.begin(), cipherText.begin() + blocksize);
            decrypted.push_back(lookup[block]);
        }
        plainText.insert(plainText.end(), decrypted.begin(), decrypted.end());
    }
    return plainText;
}

int main() {
    std::string unkownString_base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    int len = base64_decoded_size(unkownString_base64.length());
    std::vector<uint8_t> unknownstring(len);
    base64_decode(unknownstring.data(), unkownString_base64.c_str(), unkownString_base64.length());
    key = initKey();
    int guessedBlockSize = guessBlockSize(std::string(unknownstring.begin(), unknownstring.end()));
    std::vector<uint8_t> plainText = crackECB(unknownstring, guessedBlockSize);
    std::cout << "Plaintext = " << std::string(plainText.begin(), plainText.end()) << std::endl;
    return 0;
}
