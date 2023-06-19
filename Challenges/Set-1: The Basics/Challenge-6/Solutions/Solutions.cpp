
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>
#include <cassert>
#include <bitset>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <cstdint>

const std::vector<double> idealFreqs = {
    0.08167, 0.01492, 0.02792, 0.04253, 0.12702, 0.0228, 0.02015, 0.06094, 0.06966, 0.0153, 0.0772, 0.04025,
    0.02406, 0.06749, 0.07507, 0.01929, 0.0095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.0236, 0.0015,
    0.01974, 0.0074, 0.232
};

std::vector<uint8_t> hexDecode(const std::string& input) {
    std::vector<uint8_t> cipherText;
    cipherText.reserve(input.length() / 2);
    for (std::size_t i = 0; i < input.length(); i += 2) {
        std::string byteString = input.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        cipherText.push_back(byte);
    }
    return cipherText;
}

std::string xorBytes(const std::vector<uint8_t>& input, uint8_t key) {
    std::string result(input.size(), '\0');
    for (std::size_t i = 0; i < input.size(); ++i) {
        result[i] = input[i] ^ key;
    }
    return result;
}

double getScore(const std::string& input) {
    std::string inputBuffer = input;
    std::transform(inputBuffer.begin(), inputBuffer.end(), inputBuffer.begin(), ::tolower);
    std::vector<double> counter(27, 0.0);
    int total = 0;
    for (char ch : inputBuffer) {
        if ('a' <= ch && ch <= 'z') {
            counter[ch - 'a']++;
            total++;
        }
        if (ch == ' ') {
            counter[26]++;
            total++;
        }
    }
    for (double& val : counter) {
        val /= total;
    }
    double score = 0.0;
    for (std::size_t i = 0; i < counter.size(); ++i) {
        double expected = total * idealFreqs[i];
        double buffer1 = std::pow(counter[i] - expected, 2);
        double buffer = buffer1 / expected;
        score += buffer;
    }
    return score;
}

std::pair<uint8_t, std::string> bruteForce(const std::vector<uint8_t>& input) {
    double low = 400.0;
    double score;
    std::string msg;
    uint8_t key = 0;

    for (int i = 0; i < 127; ++i) {
        uint8_t k = static_cast<uint8_t>(i);
        std::string buffer = xorBytes(input, k);
        score = getScore(buffer);
        if (score < low) {
            low = score;
            key = k;
            msg = buffer;
        }
    }
    return std::make_pair(key, msg);
}

int hammingDistance(uint8_t a, uint8_t b) {
    int sum = 0;
    uint8_t r = a ^ b;
    while (r > 0) {
        if (r & 1) {
            sum++;
        }
        r = r >> 1;
    }
    return sum;
}

int guessKeySize(const std::vector<uint8_t>& cipherText) {
    int keyLen = 0;
    double maxDist = 400.0;
    int maxSize = 40;
    int blocks = cipherText.size() / maxSize;
    for (int keySize = 2; keySize < maxSize; ++keySize) {
        double dist = 0.0;
        for (int i = 0; i < blocks; ++i) {
            int a = i * keySize;
            int b = (i + 1) * keySize;
            int c = (i + 2) * keySize;
            dist += static_cast<double>(hammingDistance(cipherText[a], cipherText[b])) / keySize;
        }
        dist /= blocks;
        if (dist < maxDist) {
            maxDist = dist;
            keyLen = keySize;
        }
    }
    return keyLen;
}

std::string guessKey(const std::vector<uint8_t>& cipherText, int keySize) {
    std::string key;
    int blockSize = cipherText.size() / keySize;
    for (int i = 0; i < keySize; ++i) {
        std::vector<uint8_t> blocks(blockSize);
        for (int j = 0; j < blockSize; ++j) {
            blocks[j] = cipherText[i + j * keySize];
        }
        std::pair<uint8_t, std::string> result = bruteForce(blocks);
        key.push_back(result.first);
    }
    return key;
}

std::vector<uint8_t> decrypt(const std::string& key, const std::vector<uint8_t>& cipherText, int keySize) {
    std::vector<uint8_t> plainText(cipherText.size());
    int j = 0;
    for (std::size_t i = 0; i < cipherText.size(); ++i) {
        plainText[i] = cipherText[i] ^ key[j];
        if ((j + 1) % keySize == 0) {
            j = 0;
            continue;
        }
        j++;
    }
    return plainText;
}

int main() {
    std::string filename = "question6_data.txt";
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "Input File Error" << std::endl;
        return 1;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string filecontent = buffer.str();
    file.close();

    std::vector<uint8_t> cipherText = hexDecode(filecontent);
    int keyLen = guessKeySize(cipherText);
    std::string key = guessKey(cipherText, keyLen);
    std::cout << "Key = " << key << std::endl;
    std::cout << "\nPlainText is:\n";
    std::vector<uint8_t> plainText = decrypt(key, cipherText, keyLen);
    std::cout.write(reinterpret_cast<const char*>(plainText.data()), plainText.size());
    std::cout << std::endl;

    return 0;
}
