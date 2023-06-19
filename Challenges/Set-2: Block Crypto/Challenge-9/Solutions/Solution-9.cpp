
#include <iostream>
#include <vector>

std::vector<uint8_t> paddingPKCS7(const std::vector<uint8_t>& plainText, int blockSize) {
    int padding = blockSize - (plainText.size() % blockSize);
    std::vector<uint8_t> paddedText = plainText;

    for (int i = 0; i < padding; i++) {
        paddedText.push_back(static_cast<uint8_t>(padding));
    }

    return paddedText;
}

int main() {
    int blockSize = 20;
    std::string plainText = "YELLOW SUBMARINE";

    std::vector<uint8_t> paddedText = paddingPKCS7(std::vector<uint8_t>(plainText.begin(), plainText.end()), blockSize);

    for (const auto& byte : paddedText) {
        std::cout << static_cast<int>(byte) << " ";
    }
    std::cout << std::endl;

    return 0;
}
