
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <ctime>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

const int blockSize = 16;
unsigned char key[blockSize];
std::vector<double> idealFreqs {0.08167, 0.01492, 0.02792, 0.04253, 0.12702, 0.0228, 0.02015, 0.06094, 0.06966, 0.0153, 0.0772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.0095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 0.01974, 0.0074, 0.23200 };

void initKey()
{
    RAND_bytes(key, blockSize);
}

std::vector<unsigned char> aesCTR_encrypt(const std::vector<unsigned char>& plainText)
{
    std::vector<unsigned char> cipherText;
    int tracker = 0;
    int i = 0;

    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);

    unsigned char counter[blockSize];
    unsigned char nonce[blockSize];
    memset(counter, 0, sizeof(counter));
    memset(nonce, 0, sizeof(nonce));

    while (cipherText.size() < plainText.size())
    {
        unsigned char buffer[blockSize];
        AES_encrypt(nonce, buffer, &aesKey);

        for (i = 0; i < blockSize; i++)
        {
            if (tracker == plainText.size() - 1)
            {
                return cipherText;
            }
            cipherText.push_back(buffer[i] ^ plainText[tracker]);
            tracker++;
        }

        nonce[0]++;

        if (nonce[0] == 0)
        {
            counter[0]++;
        }
    }

    return cipherText;
}

std::string xorBytes(const std::vector<unsigned char>& input, unsigned char key)
{
    std::string result(input.size(), 0);
    for (size_t i = 0; i < input.size(); i++)
    {
        result[i] = input[i] ^ key;
    }
    return result;
}

unsigned char bruteForce(const std::vector<unsigned char>& input)
{
    double low = 400.0;
    unsigned char key = 0;

    for (int i = 0; i < 256; i++)
    {
        unsigned char k = static_cast<unsigned char>(i);
        std::string xored = xorBytes(input, k);
        std::vector<double> counter(27, 0);
        int total = 0;

        for (char ch : xored)
        {
            if ('a' <= ch && ch <= 'z')
            {
                counter[ch - 'a']++;
                total++;
            }
            if (ch == ' ')
            {
                counter[26]++;
                total++;
            }
        }

        for (int i = 0; i < 27; i++)
        {
            counter[i] /= total;
        }

        double score = chiSquare(counter, xored.length());
        if (score < low)
        {
            low = score;
            key = k;
        }
    }

    return key;
}

double chiSquare(const std::vector<double>& counter, double total)
{
    double score = 0.0;
    for (size_t i = 0; i < counter.size(); i++)
    {
        double expected = total * idealFreqs[i];
        double buffer1 = pow(counter[i] - expected, 2);
        double buffer = buffer1 / expected;
        score += buffer;
    }
    return score;
}

std::vector<unsigned char> guessKey(const std::vector<unsigned char>& cipherText, int keySize)
{
    std::vector<unsigned char> key;
    int blockSize = cipherText.size() / keySize;

    for (int i = 0; i < keySize; i++)
    {
        std::vector<unsigned char> blocks;
        for (int j = 0; j < blockSize; j++)
        {
            blocks.push_back(cipherText[i + j * keySize]);
        }
        unsigned char buffer = bruteForce(blocks);
        key.push_back(buffer);
    }

    return key;
}

std::vector<std::string> readByline(const std::string& filename, int& minLength)
{
    std::ifstream file(filename);
    std::vector<std::string> cipherTexts;
    bool init = false;

    if (!file)
    {
        std::cerr << "File read error" << std::endl;
        exit(1);
    }

    std::string line;
    while (std::getline(file, line))
    {
        std::vector<unsigned char> plaintext;
        std::string decoded;

        plaintext.resize(base64_decoded_size(line.length()));
        int decodedLength = base64_decode(&plaintext[0], line.c_str(), line.length());
        plaintext.resize(decodedLength);

        std::vector<unsigned char> ciphertext = aesCTR_encrypt(plaintext);
        decoded.resize(ciphertext.size());
        for (size_t i = 0; i < ciphertext.size(); i++)
        {
            decoded[i] = ciphertext[i];
        }

        cipherTexts.push_back(decoded);

        if (!init)
        {
            minLength = ciphertext.size();
            init = true;
        }
        else if (init && ciphertext.size() < minLength)
        {
            minLength = ciphertext.size();
        }
    }

    return cipherTexts;
}

std::string truncate(const std::vector<std::string>& cipherTexts, int minLength)
{
    std::string truncatedText;
    for (const std::string& cipherText : cipherTexts)
    {
        truncatedText += cipherText.substr(0, minLength);
    }
    return truncatedText;
}

void getPlainText(const std::string& cipherText, const std::vector<unsigned char>& key)
{
    std::string plaintext;

    for (size_t j = 0; j < cipherText.length(); j++)
    {
        unsigned char k = key[j % key.size()];
        plaintext += cipherText[j] ^ k;
    }

    std::cout << plaintext << std::endl;
}

int main()
{
    std::string filename = "Data.txt";
    int minLength;
    std::vector<std::string> cipherTexts = readByline(filename, minLength);
    std::string cipherText = truncate(cipherTexts, minLength);
    std::vector<unsigned char> key = guessKey(std::vector<unsigned char>(cipherText.begin(), cipherText.end()), minLength);
    getPlainText(cipherText, key);

    return 0;
}

