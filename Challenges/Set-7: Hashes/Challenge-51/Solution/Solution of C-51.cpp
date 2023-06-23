
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <cmath>
#include <random>
#include <stdexcept>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <zlib.h>
#include <cassert>

// Function to compress data using flate compression
std::vector<uint8_t> compress(const std::vector<uint8_t>& data) {
    z_stream zs{};
    if (deflateInit(&zs, Z_DEFAULT_COMPRESSION) != Z_OK) {
        throw std::runtime_error("deflateInit failed");
    }

    zs.next_in = const_cast<uint8_t*>(data.data());
    zs.avail_in = static_cast<uint32_t>(data.size());

    std::vector<uint8_t> compressedData(zs.avail_out);
    zs.next_out = compressedData.data();
    zs.avail_out = static_cast<uint32_t>(compressedData.size());

    if (deflate(&zs, Z_FINISH) != Z_STREAM_END) {
        throw std::runtime_error("deflate failed");
    }

    compressedData.resize(zs.total_out);
    if (deflateEnd(&zs) != Z_OK) {
        throw std::runtime_error("deflateEnd failed");
    }

    return compressedData;
}

// Function to encrypt data using AES-CTR mode
std::vector<uint8_t> encryptAESCTR(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key) {
    if (key.size() != 16) {
        throw std::invalid_argument("Invalid AES key size");
    }

    std::vector<uint8_t> iv(AES_BLOCK_SIZE);
    if (RAND_bytes(iv.data(), AES_BLOCK_SIZE) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key.data(), 128, &aesKey) != 0) {
        throw std::runtime_error("AES_set_encrypt_key failed");
    }

    AES_ctr128_encrypt(plaintext.data(), ciphertext.data(), plaintext.size(), &aesKey, iv.data(), iv.data(), nullptr);
    return ciphertext;
}

// Function to encrypt data using AES-CBC mode
std::vector<uint8_t> encryptAESCBC(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key) {
    if (key.size() != 16) {
        throw std::invalid_argument("Invalid AES key size");
    }

    std::vector<uint8_t> iv(AES_BLOCK_SIZE);
    if (RAND_bytes(iv.data(), AES_BLOCK_SIZE) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }

    size_t paddedSize = (plaintext.size() / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    std::vector<uint8_t> paddedPlaintext(paddedSize);
    std::memcpy(paddedPlaintext.data(), plaintext.data(), plaintext.size());

    std::vector<uint8_t> ciphertext(paddedSize);
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key.data(), 128, &aesKey) != 0) {
        throw std::runtime_error("AES_set_encrypt_key failed");
    }

    AES_cbc_encrypt(paddedPlaintext.data(), ciphertext.data(), paddedSize, &aesKey, iv.data(), AES_ENCRYPT);
    return ciphertext;
}

// Function to format the request
std::vector<uint8_t> formatRequest(const std::vector<uint8_t>& payload) {
    std::string request = "POST / HTTP/1.1\n"
                          "Host: hapless.com\n"
                          "Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n"
                          "Content-Length: " + std::to_string(payload.size()) + "\n\n";

    std::vector<uint8_t> formattedRequest(request.begin(), request.end());
    formattedRequest.insert(formattedRequest.end(), payload.begin(), payload.end());
    return formattedRequest;
}

// Function to compute the score for stream cipher cracking
int streamCipherOracle(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> formattedData = formatRequest(data);
    std::vector<uint8_t> compressedData = compress(formattedData);
    return compressedData.size();
}

// Function to find the next stream cipher candidates
std::vector<std::string> findNextStreamCipherCandidates(const std::vector<std::string>& candidates) {
    std::vector<std::string> best;
    int bestScore = std::numeric_limits<int>::max();
    std::vector<uint8_t> base64 = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
        'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };

    for (const std::string& candidate : candidates) {
        for (uint8_t i = 0; i < base64.size(); i++) {
            std::string newCandidate = candidate + base64[i];
            int score = streamCipherOracle(std::vector<uint8_t>(newCandidate.begin(), newCandidate.end()));
            if (score < bestScore) {
                bestScore = score;
                best = { newCandidate };
            } else if (score == bestScore) {
                best.push_back(newCandidate);
            }
        }
    }

    return best;
}

// Function to crack the stream cipher
std::string crackStreamCipher() {
    std::vector<std::string> candidates = { "sessionid=" };

    for (int i = 0; i < 43; i++) {
        candidates = findNextStreamCipherCandidates(candidates);
    }

    if (candidates.size() != 1) {
        throw std::runtime_error("Failed to crack session");
    }

    return candidates[0] + "=";
}

// Function to compute the score for block cipher cracking
int blockCipherOracle(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> formattedData = formatRequest(data);
    std::vector<uint8_t> compressedData = compress(formattedData);
    return compressedData.size();
}

// Function to find the next block cipher candidates
std::vector<std::string> findNextBlockCipherCandidates(const std::vector<std::string>& candidates, const std::vector<uint8_t>& prefix) {
    std::vector<uint8_t> base64 = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
        'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };

    std::vector<std::string> best;
    int bestScore = std::numeric_limits<int>::max();

    for (const std::string& candidate : candidates) {
        for (uint8_t i = 0; i < base64.size(); i++) {
            std::string newCandidate = prefix;
            newCandidate += candidate + base64[i];
            int score = blockCipherOracle(std::vector<uint8_t>(newCandidate.begin(), newCandidate.end()));
            if (score < bestScore) {
                bestScore = score;
                best = { newCandidate };
            } else if (score == bestScore) {
                best.push_back(newCandidate);
            }
        }
    }

    return best;
}

// Function to crack the block cipher
std::string crackBlockCipher() {
    std::vector<std::string> candidates = { "sessionid=" };
    std::vector<uint8_t> prefix;

    while (true) {
        std::vector<std::string> best = findNextBlockCipherCandidates(candidates, prefix);
        if (best.size() != 64) {
            return best[0] + "=";
        }
        prefix.push_back(static_cast<uint8_t>(prefix.size()));
        if (prefix.size() > 100) {
            throw std::runtime_error("Failed to find best byte");
        }
    }
}

// Main function to solve challenge 51
void challenge51() {
    std::cout << "part 1: stream cipher" << std::endl;
    std::string session = crackStreamCipher();
    std::cout << "secret: " << session << std::endl;
    if (session == "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=") {
        std::cout << "success!" << std::endl;
    } else {
        throw std::runtime_error("Failed to crack session");
    }
    std::cout << std::endl;

    std::cout << "part 2: block cipher" << std::endl;
    session = crackBlockCipher();
    std::cout << "secret: " << session << std::endl;
    if (session == "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=") {
        std::cout << "success!" << std::endl;
    } else {
        throw std::runtime_error("Failed to crack session");
    }
    std::cout << std::endl;
}

int main() {
    try {
        challenge51();
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
