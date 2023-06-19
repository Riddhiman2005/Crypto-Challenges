
#include <iostream>
#include <vector>
#include <cmath>

int blockSize = 16;

bool validPadding(const std::vector<uint8_t>& plainTextPadded) {
    int padding = plainTextPadded[plainTextPadded.size() - 1];
    int messageLen = plainTextPadded.size() - padding;
    int rfcPadding = blockSize - fmod(messageLen, blockSize);
    for (size_t i = plainTextPadded.size() - rfcPadding; i < plainTextPadded.size(); i++) {
        if (plainTextPadded[i] != rfcPadding) {
            return false;
        }
    }
    return true;
}

std::vector<uint8_t> stripPadding(const std::vector<uint8_t>& plainTextPadded) {
    int paddingLen = plainTextPadded[plainTextPadded.size() - 1];
    std::vector<uint8_t> plainText(plainTextPadded.begin(), plainTextPadded.end() - paddingLen);
    return plainText;
}

int main() {
    std::vector<uint8_t> plainTextPadded = { 'I', 'C', 'E', ' ', 'I', 'C', 'E', ' ', 'B', 'A', 'B', 'Y', 0x04, 0x04, 0x04, 0x04 };
    if (validPadding(plainTextPadded)) {
        std::cout << "Valid Padding" << std::endl;
        std::vector<uint8_t> plainText = stripPadding(plainTextPadded);
        std::cout << "PlainText = " << std::string(plainText.begin(), plainText.end()) << std::endl;
    } else {
        std::cout << "Invalid Padding" << std::endl;
    }
    return 0;
}

