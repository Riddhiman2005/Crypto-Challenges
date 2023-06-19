
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <iomanip>

std::vector<uint8_t> xorCipher(const std::vector<uint8_t>& text, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> result(text.size());
    std::size_t keySize = key.size();
    std::size_t j = 0;
    for (std::size_t i = 0; i < text.size(); i++) {
        result[i] = text[i] ^ key[j];
        j = (j + 1) % keySize;
    }
    return result;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

int main() {
    std::string filename = "Input.txt";
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "File Error" << std::endl;
        return 1;
    }

    std::vector<uint8_t> text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    std::string key = "ICE";
    std::vector<uint8_t> buffer = xorCipher(text, std::vector<uint8_t>(key.begin(), key.end()));
    std::string result = bytesToHex(buffer);
    std::cout << result << std::endl;

    return 0;
}

