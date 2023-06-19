
#include <iostream>
#include <vector>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cmath>
#include <map>

int blockSize = 16;
std::vector<uint8_t> key;

std::vector<uint8_t> initKey() {
    srand(time(NULL));
    std::vector<uint8_t> key(blockSize);
    RAND_bytes(key.data(), key.size());
    return key;
}

std::vector<uint8_t> removePadding(const std::vector<uint8_t>& plaintextPadded) {
    uint8_t paddingBytes = plaintextPadded[plaintextPadded.size() - 1];
    std::vector<uint8_t> plainText(plaintextPadded.begin(), plaintextPadded.end() - paddingBytes);
    return plainText;
}

std::vector<uint8_t> paddingPKCS7(const std::vector<uint8_t>& plainText) {
    int padding = blockSize - (plainText.size() % blockSize);
    std::vector<uint8_t> paddedText = plainText;
    for (int i = 0; i < padding; i++) {
        paddedText.push_back(padding);
    }
    return paddedText;
}

std::vector<uint8_t> aesECBDecrypt(const std::vector<uint8_t>& cipherText) {
    if (cipherText.size() % blockSize != 0) {
        std::cout << "Padding Error" << std::endl;
        exit(1);
    }
    AES_KEY aesKey;
    AES_set_decrypt_key(key.data(), 128, &aesKey);
    std::vector<uint8_t> plainTextPadded(cipherText.size());
    for (size_t i = 0; i < cipherText.size(); i += blockSize) {
        AES_decrypt(cipherText.data() + i, plainTextPadded.data() + i, &aesKey);
    }
    return removePadding(plainTextPadded);
}

std::vector<uint8_t> aesECBEncrypt(const std::vector<uint8_t>& plainText) {
    if (plainText.size() % blockSize != 0) {
        std::cout << "Padding Error" << std::endl;
        exit(1);
    }
    AES_KEY aesKey;
    AES_set_encrypt_key(key.data(), 128, &aesKey);
    std::vector<uint8_t> cipherText(plainText.size());
    for (size_t i = 0; i < plainText.size(); i += blockSize) {
        AES_encrypt(plainText.data() + i, cipherText.data() + i, &aesKey);
    }
    return cipherText;
}

std::vector<uint8_t> profileFor(const std::string& email) {
    std::string encodedEmail = "email=" + email;
    return paddingPKCS7(std::vector<uint8_t>(encodedEmail.begin(), encodedEmail.end())) + std::vector<uint8_t>{'&', 'u', 'i', 'd', '=', '1', '0', '&', 'r', 'o', 'l', 'e', '=', 'u', 's', 'e', 'r'};
}

bool metaCharCheck(const std::string& email) {
    return email.find('&') == std::string::npos && email.find('=') == std::string::npos;
}

std::vector<uint8_t> getChosenCipherText() {
    std::string plainText = "&role=admin";
    std::vector<uint8_t> cipherTextPadded = paddingPKCS7(std::vector<uint8_t>(plainText.begin(), plainText.end()));
    return aesECBEncrypt(cipherTextPadded);
}

std::vector<uint8_t> cutAndPaste(const std::vector<uint8_t>& orgCipherText) {
    std::vector<uint8_t> newCipherText(orgCipherText.begin(), orgCipherText.begin() + 32);
    std::vector<uint8_t> chosenCipherText = getChosenCipherText();
    newCipherText.insert(newCipherText.end(), chosenCipherText.begin(), chosenCipherText.end());
    return newCipherText;
}

int main() {
    key = initKey();
    std::string email = "random@random.com";
    if (!metaCharCheck(email)) {
        std::cout << "Check for meta characters" << std::endl;
        exit(1);
    }
    std::vector<uint8_t> profileEncoded = profileFor(email);
    std::vector<uint8_t> cipherText = aesECBEncrypt(profileEncoded);
    std::cout << "Original CipherText: " << std::string(cipherText.begin(), cipherText.end()) << std::endl;
    std::vector<uint8_t> plainText = aesECBDecrypt(cipherText);
    std::cout << "Original Decryption: " << std::string(plainText.begin(), plainText.end()) << std::endl;
    std::vector<uint8_t> newCipherText = cutAndPaste(cipherText);
    std::cout << "New CipherText: " << std::string(newCipherText.begin(), newCipherText.end()) << std::endl;
    std::vector<uint8_t> newPlainText = aesECBDecrypt(newCipherText);
    std::cout << "New PlainText: " << std::string(newPlainText.begin(), newPlainText.end()) << std::endl;
    return 0;
}

