
#include <iostream>
#include <string>
#include <vector>
#include <openssl/sha.h>

std::vector<unsigned char> sha1(const std::vector<unsigned char>& message) {
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, message.data(), message.size());

    std::vector<unsigned char> digest(SHA_DIGEST_LENGTH);
    SHA1_Final(digest.data(), &ctx);

    return digest;
}

std::vector<unsigned char> secretPrefixMAC(const std::vector<unsigned char>& key, const std::vector<unsigned char>& message) {
    std::vector<unsigned char> keyMessage = key;
    keyMessage.insert(keyMessage.end(), message.begin(), message.end());
    return sha1(keyMessage);
}

bool verifyMAC(const std::vector<unsigned char>& key, const std::vector<unsigned char>& message, const std::vector<unsigned char>& mac) {
    std::vector<unsigned char> calculatedMac = secretPrefixMAC(key, message);
    return calculatedMac == mac;
}

int main() {
    std::string secretKey = "mysecretkey";
    std::string message = "Hello, world!";
    
    std::vector<unsigned char> key(secretKey.begin(), secretKey.end());
    std::vector<unsigned char> msg(message.begin(), message.end());
    
    // Calculate MAC
    std::vector<unsigned char> mac = secretPrefixMAC(key, msg);
    
    // Verify MAC
    bool isValid = verifyMAC(key, msg, mac);
    
    std::cout << "Message: " << message << std::endl;
    std::cout << "Key: " << secretKey << std::endl;
    
    std::cout << "MAC: ";
    for (const auto& byte : mac) {
        printf("%02x", byte);
    }
    std::cout << std::endl;
    
    std::cout << "MAC verification: " << (isValid ? "valid" : "invalid") << std::endl;
    
    return 0;
}
