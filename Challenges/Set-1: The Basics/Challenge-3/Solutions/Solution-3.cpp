
// C++ code as the solution of the posed Challenge-3

#include <iostream>
#include <string>
#include <cmath>

const double idealFreqs[] = {0.08167, 0.01492, 0.02792, 0.04253, 0.12702, 0.0228, 0.02015, 0.06094, 0.06966, 0.0153, 0.0772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.0095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.0074, 0.23200};

std::string hexDecode(const std::string& input) {
    std::string cipherText;
    for (std::size_t i = 0; i < input.length(); i += 2) {
        std::string byteString = input.substr(i, 2);
        char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
        cipherText.push_back(byte);
    }
    return cipherText;
}

std::string xorBytes(const std::string& input, char key) {
    std::string result = input;
    for (std::size_t i = 0; i < input.length(); i++) {
        result[i] = input[i] ^ key;
    }
    return result;
}

double getScore(const std::string& input) {
    std::string inputBuffer = input;
    for (char& ch : inputBuffer) {
        ch = std::tolower(ch);
    }

    double counter[27] = {0.0};
    int total = 0;

    for (char ch : inputBuffer) {
        if ('a' <= ch && ch <= 'z') {
            counter[ch - 'a']++;
            total++;
        }
        if (ch == ' ') {
            total++;
            counter[26]++;
        }
    }

    for (int i = 0; i < 27; i++) {
        counter[i] /= total;
    }

    double score = chiSquare(counter, input.length());
    return score;
}

double chiSquare(const double counter[], double total) {
    double score = 0.0;
    for (int i = 0; i < 27; i++) {
        double expected = total * idealFreqs[i];
        double buffer = std::pow(counter[i] - expected, 2) / expected;
        score += buffer;
    }
    return score;
}

std::string bruteForce(const std::string& cipherText) {
    double lowestScore = 1000.0;
    std::string decryptedMessage;
    char key = '\0';

    for (int i = 0; i < 256; i++) {
        char k = static_cast<char>(i);
        std::string buffer = xorBytes(cipherText, k);
        double score = getScore(buffer);
        if (score < lowestScore) {
            lowestScore = score;
            key = k;
            decryptedMessage = buffer;
        }
    }
    return decryptedMessage;
}

int main() {
    std::string cipherTextHex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    std::string cipherText = hexDecode(cipherTextHex);
    std::string key = bruteForce(cipherText);

    std::cout << "Key: " << static_cast<int>(key[0]) << std::endl;
    std::cout << "Decrypted Message: " << key << std::endl;

    return 0;
}
