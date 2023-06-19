
#include <iostream>
#include <vector>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

std::vector<uint8_t> xorBytes(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); i++) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

std::vector<uint8_t> cbcDecrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> plaintext(ciphertext.size());
    std::vector<uint8_t> buffer(16);
    std::vector<uint8_t> iv(16, 0); // Initialization vector
    int blocksize = 16;
    bool init = true;

    AES_KEY aesKey;
    AES_set_decrypt_key(key.data(), 128, &aesKey);

    for (size_t i = blocksize; i <= ciphertext.size(); i += blocksize) {
        if (init) {
            AES_decrypt(ciphertext.data() + i - blocksize, buffer.data(), &aesKey);
            memcpy(plaintext.data() + i - blocksize, xorBytes(iv, buffer).data(), blocksize);
            init = false;
        } else {
            AES_decrypt(ciphertext.data() + i - blocksize, buffer.data(), &aesKey);
            memcpy(plaintext.data() + i - blocksize, xorBytes(ciphertext, buffer).data() + i - (2 * blocksize), blocksize);
        }
    }
    return plaintext;
}

int main() {
    std::vector<uint8_t> key = {'Y', 'E', 'L', 'L', 'O', 'W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    std::string filename = "Input.txt";

    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cout << "File Error" << std::endl;
        return 1;
    }

    std::streamsize size = file.tellg();
    std::vector<uint8_t> ciphertext(size);
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(ciphertext.data()), size)) {
        std::cout << "Read Error" << std::endl;
        return 1;
    }

    std::vector<uint8_t> plaintext = cbcDecrypt(ciphertext, key);
    std::cout << std::string(plaintext.begin(), plaintext.end()) << std::endl;

    return 0;
}
