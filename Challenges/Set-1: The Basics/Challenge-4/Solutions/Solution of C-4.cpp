
// C++ code to solve the Challenge-4


#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
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

std::string xorBytes(const std::string& input, const std::string& key) {
    std::string result;
    std::size_t keySize = key.length();
    std::size_t j = 0;
    for (std::size_t i = 0; i < input.length(); i++) {
        char byte = input[i] ^ key[j];
        result.push_back(byte);
        j++;
        if (j == keySize) {
            j = 0;
        }
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

void bruteForce(const std::string& cipherText, char& key, std::string& message, double& low) {
    bool flag = false;
    key = '\0';

    for (int i = 0; i < 256; i++) {
        std::string buffer = xorBytes(cipherText, std::string(1, static_cast<char>(i)));
        double score = getScore(buffer);
        if (!flag) {
            low = score;
            flag = true;
        }
        else if (score <= low && flag) {
            low = score;
            key = static_cast<char>(i);
            message = buffer;
        }
    }
}

int main() {
    std::string message;
    char key = '\0';
    std::string cipherText;
    bool flag = false;
    double min = 0.0;
    std::string filename = "question4_data.txt";
    std::ifstream file(filename);
    std::string line;
    while (std::getline(file, line)) {
        std::string cipherTextHex = line;
        std::string cipherTextUnhex = hexDecode(cipherTextHex);
        bruteForce(cipherTextUnhex, key, message, min);
        if (!flag) {
            cipherText = cipherTextHex;
            min = getScore(message);
            flag = true;
        }
        else if (getScore(message) < min) {
            cipherText = cipherTextHex;
            min = getScore(message);
        }
    }
    file.close();

    std::cout << "Message: " << message << std::endl;
    std::cout << "Key: " << static_cast<int>(key) << std::endl;
    std::cout << "CipherText: " << cipherText << std::endl;

    return 0;
}
