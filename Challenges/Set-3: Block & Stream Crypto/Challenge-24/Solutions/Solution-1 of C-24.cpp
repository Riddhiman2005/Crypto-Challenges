
#include <iostream>
#include <random>
#include <chrono>

// Encrypt plaintext using MT19937 stream cipher with a 16-bit seed
std::string encrypt(const std::string& plaintext, uint16_t seed) {
    std::mt19937 mt(seed);
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    
    std::string ciphertext;
    for (char c : plaintext) {
        uint8_t keystreamByte = dist(mt);
        ciphertext += (c ^ keystreamByte);
    }
    
    return ciphertext;
}

// Decrypt ciphertext using MT19937 stream cipher with a 16-bit seed
std::string decrypt(const std::string& ciphertext, uint16_t seed) {
    return encrypt(ciphertext, seed); // Stream cipher is symmetric
}

// Recover the seed used to encrypt the known plaintext
uint16_t recoverSeed(const std::string& ciphertext, const std::string& knownPlaintext) {
    for (uint16_t seed = 0; seed <= std::numeric_limits<uint16_t>::max(); ++seed) {
        std::string decrypted = decrypt(ciphertext, seed);
        if (decrypted.substr(0, knownPlaintext.size()) == knownPlaintext) {
            return seed;
        }
    }
    
    return 0; // Seed not found
}

// Check if a given password token is generated from MT19937 seeded with the current time
bool isPasswordTokenFromCurrentTime(uint32_t token) {
    auto currentTime = std::chrono::system_clock::now().time_since_epoch().count();
    std::mt19937 mt(currentTime);
    
    return (token == mt());
}

int main() {
    // Encrypt plaintext using MT19937 stream cipher
    std::string plaintext = "AAAAAAAAAAAAAA";
    uint16_t seed = 12345;
    std::string ciphertext = encrypt(plaintext, seed);
    
    // Decrypt ciphertext using MT19937 stream cipher
    std::string decrypted = decrypt(ciphertext, seed);
    
    std::cout << "Plaintext: " << plaintext << std::endl;
    std::cout << "Ciphertext: " << ciphertext << std::endl;
    std::cout << "Decrypted: " << decrypted << std::endl;
    
    // Recover the seed from ciphertext and known plaintext
    uint16_t recoveredSeed = recoverSeed(ciphertext, plaintext);
    std::cout << "Recovered Seed: " << recoveredSeed << std::endl;
    
    // Generate a random password reset token using MT19937 seeded with the current time
    uint32_t passwordToken;
    {
        auto currentTime = std::chrono::system_clock::now().time_since_epoch().count();
        std::mt19937 mt(currentTime);
        passwordToken = mt();
    }
    
    // Check if a given password token is from MT19937 seeded with the current time
    bool isValidToken = isPasswordTokenFromCurrentTime(passwordToken);
    
    std::cout << "Password Token: " << passwordToken << std::endl;
    std::cout << "Is Valid Token: " << (isValidToken ? "Yes" : "No") << std::endl;
    
    return 0;
}
