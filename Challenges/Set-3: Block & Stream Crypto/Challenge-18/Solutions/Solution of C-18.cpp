#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cstring>

const std::string key = "YELLOW SUBMARINE";
const int blockSize = 16;

std::vector<uint8_t> aesCTR_decrypt(const std::vector<uint8_t>& cipherText) {
    std::vector<uint8_t> plainText;
    int tracker = 0;
    int i = 0;
    int block_count = 0;
    AES_KEY aesKey;
    if (AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &aesKey) < 0) {
        std::cerr << "AES error" << std::endl;
        exit(1);
    }
    int64_t counter = 0;
    int64_t nonce = 0;
    std::vector<uint8_t> nonce_byte(8);
    std::vector<uint8_t> counter_byte(8);
    if (cipherText.size() % blockSize == 0) {
        block_count = cipherText.size() / blockSize;
    } else {
        block_count = cipherText.size() / blockSize;
        block_count++;
    }
    while (plainText.size() <= cipherText.size()) {
        std::vector<uint8_t> buffer(blockSize);
        memcpy(nonce_byte.data(), &nonce, 8);
        memcpy(counter_byte.data(), &counter, 8);
        AES_encrypt(nonce_byte.data(), buffer.data(), &aesKey);
        for (i = 0; i < 16; i++) {
            if (tracker == cipherText.size() - 1) {
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

int main() {
    std::string ciphertext_bs64 = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    std::vector<uint8_t> cipherText;
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(const_cast<char*>(ciphertext_bs64.c_str()), ciphertext_bs64.size());
    mem = BIO_push(b64, mem);

    char buffer[1024];
    int bytesRead = 0;
    while ((bytesRead = BIO_read(mem, buffer, sizeof(buffer))) > 0) {
        cipherText.insert(cipherText.end(), buffer, buffer + bytesRead);
    }
    BIO_free_all(mem);

    std::vector<uint8_t> plainText = aesCTR_decrypt(cipherText);
    std::cout << std::string(plainText.begin(), plainText.end()) << std::endl;

    return 0;
}
