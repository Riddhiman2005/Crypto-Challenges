
#include <iostream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <random>
#include <algorithm>
#include <iterator>

#include <openssl/aes.h>

const int blocksize = 16;
std::vector<unsigned char> key(blocksize);

void initKey() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < blocksize; i++) {
        key[i] = static_cast<unsigned char>(dis(gen));
    }
}

std::vector<unsigned char> aesCTR_decrypt(const std::vector<unsigned char>& cipherText) {
    std::vector<unsigned char> plainText;
    int tracker = 0;
    int i = 0;
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key.data(), blocksize * 8, &aesKey) < 0) {
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
        AES_encrypt(nonce_byte.data(), buffer.data(), &aesKey);
        AES_encrypt(counter_byte.data(), buffer.data() + 8, &aesKey);
        for (i = 0; i < blocksize; i++) {
            if (tracker == cipherText.size()) {
                return plainText;
            }
            plainText.push_back(buffer[i] ^ cipherText[tracker]);
            tracker++;
        }
        nonce = 0;
        counter++;
    }
    return plainText;
}

std::vector<unsigned char> aesCTR_encrypt(const std::vector<unsigned char>& plainText) {
    std::vector<unsigned char> cipherText;
    int tracker = 0;
    int i = 0;
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key.data(), blocksize * 8, &aesKey) < 0) {
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
        AES_encrypt(nonce_byte.data(), buffer.data(), &aesKey);
        AES_encrypt(counter_byte.data(), buffer.data() + 8, &aesKey);
        for (i = 0; i < blocksize; i++) {
            if (tracker == plainText.size()) {
                return cipherText;
            }
            cipherText.push_back(buffer[i] ^ plainText[tracker]);
            tracker++;
        }
        nonce = 0;
        counter++;
    }
    return cipherText;
}

std::vector<unsigned char> prependData(const std::vector<unsigned char>& plaintext) {
    std::string data = "comment1=cooking%20MCs;userdata=";
    std::vector<unsigned char> result(data.begin(), data.end());
    result.insert(result.end(), plaintext.begin(), plaintext.end());
    return result;
}

std::vector<unsigned char> quoteOut(const std::vector<unsigned char>& plainText) {
    std::string buffer(plainText.begin(), plainText.end());
    std::replace(buffer.begin(), buffer.end(), ';', '?');
    std::replace(buffer.begin(), buffer.end(), '=', '?');
    return std::vector<unsigned char>(buffer.begin(), buffer.end());
}

std::vector<unsigned char> appendData(const std::vector<unsigned char>& plaintext) {
    std::string data = ";comment2=%20like%20a%20pound%20of%20bacon";
    std::vector<unsigned char> result(plaintext.begin(), plaintext.end());
    result.insert(result.end(), data.begin(), data.end());
    return result;
}

std::vector<unsigned char> getModifiedCipherText(const std::vector<unsigned char>& cipherText) {
    std::vector<unsigned char> cipherText_block(blocksize);
    std::copy(cipherText.begin() + 32, cipherText.begin() + 48, cipherText_block.begin());
    cipherText_block[0] = cipherText_block[0] ^ ';' ^ 'A';
    cipherText_block[11] = cipherText_block[11] ^ ';' ^ 'A';
    cipherText_block[6] = cipherText_block[6] ^ '=' ^ 'A';
    std::copy(cipherText_block.begin(), cipherText_block.end(), cipherText.begin() + 32);
    return cipherText;
}

std::pair<bool, std::vector<unsigned char>> attackSuccess(const std::vector<unsigned char>& cipherText) {
    std::vector<unsigned char> cipherText_new = getModifiedCipherText(cipherText);
    std::vector<unsigned char> plaintext_new = aesCTR_decrypt(cipherText_new);
    std::string plaintext_str(plaintext_new.begin(), plaintext_new.end());
    bool flag = plaintext_str.find(";admin=true;") != std::string::npos;
    return std::make_pair(flag, plaintext_new);
}

int main() {
    initKey();

    std::string userData = "AadminAtrueA";
    std::vector<unsigned char> plaintext(userData.begin(), userData.end());
    plaintext = prependData(plaintext);
    plaintext = appendData(plaintext);
    plaintext = quoteOut(plaintext);

    std::cout << "Original Plaintext: " << std::string(plaintext.begin(), plaintext.end()) << std::endl;

    std::vector<unsigned char> cipherText = aesCTR_encrypt(plaintext);
    auto [flag, new_plaintext] = attackSuccess(cipherText);

    if (flag) {
        std::cout << "Attack Success" << std::endl;
        std::cout << "New Plaintext: " << std::string(new_plaintext.begin(), new_plaintext.end()) << std::endl;
    } else {
        std::cout << "Attack Fail" << std::endl;
    }

    return 0;
}
