
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <random>
#include <cmath>
#include <algorithm>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

std::vector<uint8_t> key;
constexpr size_t blockSize = 16;
constexpr std::array<double, 27> idealFreqs = {
    .08167, .01492, .02792, .04253, .12702, .0228, .02015, .06094, .06966,
    .0153,  .0772,  .04025, .02406, .06749, .07507, .01929, .0095,  .05987,
    .06327, .09056, .02758, .00978, .02360, .00150, .01974, .0074,  0.23200};

std::vector<uint8_t> aesCTR_encrypt(const std::vector<uint8_t>& plainText)
{
    std::vector<uint8_t> cipherText;
    size_t tracker = 0;
    size_t i = 0;
    AES_KEY aesKey;

    AES_set_encrypt_key(key.data(), 128, &aesKey);

    uint64_t counter = 0;
    uint64_t nonce = 0;

    std::vector<uint8_t> nonce_byte(8, 0);
    std::vector<uint8_t> counter_byte(8, 0);

    while (cipherText.size() < plainText.size())
    {
        std::vector<uint8_t> buffer(blockSize, 0);
        memcpy(nonce_byte.data(), &nonce, sizeof(nonce));
        memcpy(counter_byte.data(), &counter, sizeof(counter));

        AES_encrypt(nonce_byte.data(), buffer.data(), &aesKey);
        for (i = 0; i < 16; ++i)
        {
            if (tracker == plainText.size() - 1)
                return cipherText;

            cipherText.push_back(buffer[i] ^ plainText[tracker]);
            ++tracker;
        }

        nonce = 0;
        counter = 0;
    }

    return cipherText;
}

std::vector<std::string> readByline(const std::string& filename)
{
    std::vector<std::string> cipherText(40);

    std::ifstream file(filename);
    if (!file)
    {
        std::cout << "File read error" << std::endl;
        std::exit(1);
    }

    std::string line;
    size_t i = 0;
    while (std::getline(file, line) && i < 40)
    {
        std::vector<uint8_t> plaintext;
        size_t decodedLen = EVP_DecodedLength(line.length());
        plaintext.resize(decodedLen);
        EVP_DecodeBase64(plaintext.data(), &decodedLen, line.c_str(), line.length());

        std::vector<uint8_t> ciphertext = aesCTR_encrypt(plaintext);
        cipherText[i] = std::string(ciphertext.begin(), ciphertext.end());
        ++i;
    }

    return cipherText;
}

double getScore(const std::string& input)
{
    std::string input_buffer = input;
    std::transform(input_buffer.begin(), input_buffer.end(), input_buffer.begin(), ::tolower);

    std::vector<double> counter(27, 0.0);
    size_t total = 0;

    for (char ch : input_buffer)
    {
        if ('a' <= ch && ch <= 'z')
        {
            counter[ch - 'a']++;
            total++;
        }
        if (ch == ' ')
        {
            total++;
            counter[26]++;
        }
    }

    for (size_t i = 0; i < counter.size(); ++i)
    {
        counter[i] /= total;
    }

    double score = chiSquare(counter, input.size());
    return score;
}

double chiSquare(const std::vector<double>& counter, size_t total)
{
    double score = 0.0;
    double buffer = 0.0;

    for (size_t i = 0; i < counter.size(); ++i)
    {
        double expected = total * idealFreqs[i];
        double buffer1 = std::pow(counter[i] - expected, 2);
        buffer = buffer1 / expected;
        score += buffer;
    }

    return score;
}

uint8_t bruteForce(const std::vector<uint8_t>& input)
{
    double low = 400.0;
    uint8_t key = 0;

    for (int i = 0; i < 256; ++i)
    {
        uint8_t k = static_cast<uint8_t>(i);
        std::vector<uint8_t> buffer = xorBytes(input, k);
        double score = getScore(std::string(buffer.begin(), buffer.end()));

        if (score < low)
        {
            low = score;
            key = k;
        }
    }

    return key;
}

std::vector<uint8_t> xorBytes(const std::vector<uint8_t>& input, uint8_t key)
{
    std::vector<uint8_t> result(input.size());

    for (size_t i = 0; i < input.size(); ++i)
    {
        result[i] = input[i] ^ key;
    }

    return result;
}

std::vector<uint8_t> guessKeyStream(const std::vector<std::string>& cipherText)
{
    std::vector<uint8_t> key;

    for (size_t i = 0; i < 16; ++i)
    {
        std::vector<uint8_t> blocks(40);
        for (size_t j = 0; j < 40; ++j)
        {
            blocks[j] = static_cast<uint8_t>(cipherText[j][i]);
        }

        uint8_t buffer = bruteForce(blocks);
        key.push_back(buffer);
    }

    return key;
}

void getPlainText(const std::vector<std::string>& cipherText, const std::vector<uint8_t>& key)
{
    for (size_t i = 0; i < 40; ++i)
    {
        std::vector<uint8_t> plaintext;
        for (size_t j = 0; j < cipherText[i].size(); ++j)
        {
            size_t k = j % 16;
            plaintext.push_back(static_cast<uint8_t>(cipherText[i][j]) ^ key[k]);
        }
        std::cout << std::string(plaintext.begin(), plaintext.end()) << std::endl;
    }
}

int main()
{
    std::string filename = "Data.txt";
    std::vector<std::string> cipherText = readByline(filename);
    getPlainText(cipherText, guessKeyStream(cipherText));

    return 0;
}
