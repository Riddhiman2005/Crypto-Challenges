
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipherText, const std::string& key) {
    std::vector<uint8_t> plainText(cipherText.size());

    AES_KEY aesKey;
    AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &aesKey);

    for (size_t i = 0; i < cipherText.size(); i += AES_BLOCK_SIZE) {
        AES_decrypt(&cipherText[i], &plainText[i], &aesKey);
    }

    return plainText;
}

std::string base64Decode(const std::string& input) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* bio = BIO_new_mem_buf(input.c_str(), static_cast<int>(input.size()));
    bio = BIO_push(b64, bio);

    std::string output;
    output.resize(input.size() * 3 / 4);
    int length = BIO_read(bio, output.data(), static_cast<int>(output.size()));
    output.resize(length);

    BIO_free_all(bio);
    return output;
}

int main() {
    std::string key = "YELLOW SUBMARINE";
    std::string filename = "Input.txt";

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "File Error" << std::endl;
        return 1;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string fileContent = buffer.str();
    file.close();

    std::string base64Text = base64Decode(fileContent);
    std::vector<uint8_t> cipherText(base64Text.begin(), base64Text.end());
    
    if (cipherText.size() % AES_BLOCK_SIZE != 0) {
        std::cout << "File Size Error" << std::endl;
        return 1;
    }

    std::vector<uint8_t> plainText = decrypt(cipherText, key);
    std::cout.write(reinterpret_cast<const char*>(plainText.data()), plainText.size());
    std::cout << std::endl;

    return 0;
}
