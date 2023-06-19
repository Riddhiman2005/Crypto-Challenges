
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

bool detectECB(const std::vector<uint8_t>& cipherText) {
    std::unordered_set<std::string> tracker;
    bool init = false;

    for (size_t i = 16; i <= cipherText.size(); i++) {
        if (!init) {
            std::string block(cipherText.begin() + i - 16, cipherText.begin() + i);
            tracker.insert(block);
            init = true;
        } else {
            std::string block(cipherText.begin() + i - 16, cipherText.begin() + i);
            if (tracker.count(block) > 0) {
                return true;
            } else {
                tracker.insert(block);
            }
        }
    }

    return false;
}

std::vector<uint8_t> hexDecode(const std::string& input) {
    std::vector<uint8_t> cipherText;
    cipherText.resize(input.size() / 2);

    for (size_t i = 0; i < input.size(); i += 2) {
        std::string hexByte = input.substr(i, 2);
        cipherText[i / 2] = static_cast<uint8_t>(std::stoi(hexByte, nullptr, 16));
    }

    return cipherText;
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
    std::string filename = "Inputut.txt";
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cout << "File Read Error" << std::endl;
        return 1;
    }

    std::vector<std::string> fileContent;
    std::string line;
    while (std::getline(file, line)) {
        fileContent.push_back(line);
    }
    file.close();

    for (const auto& cipherTextHex : fileContent) {
        std::vector<uint8_t> cipherText = hexDecode(cipherTextHex);
        if (detectECB(cipherText)) {
            std::cout << cipherTextHex << std::endl;
            return 0;
        }
    }

    return 0;
}

