
#include <iostream>
#include <random>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>

// Function to compute (base^exponent) % modulus using the right-to-left binary method

unsigned long long modularPow(unsigned long long base, unsigned long long exponent, unsigned long long modulus) {
    if (modulus == 0) {
        return 0;
    }

    unsigned long long result = 1;
    base %= modulus;

    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        exponent >>= 1;
        base = (base * base) % modulus;
    }

    return result;
}

class DiffieHellman {
private:
    unsigned long long DEFAULT_G = 2;
    unsigned long long DEFAULT_P = 0xffffffffffffffffULL;

    unsigned long long g;
    unsigned long long p;
    unsigned long long secretKey;
    unsigned long long sharedKey;

public:
    DiffieHellman(unsigned long long g = DEFAULT_G, unsigned long long p = DEFAULT_P) : g(g), p(p) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<unsigned long long> dist(0, p - 1);
        secretKey = dist(gen);
        sharedKey = 0;
    }

    unsigned long long getPublicKey() {
        return modularPow(g, secretKey, p);
    }

    unsigned long long getSharedSecretKey(unsigned long long otherPartyPublicKey) {
        if (sharedKey == 0) {
            sharedKey = modularPow(otherPartyPublicKey, secretKey, p);
        }
        return sharedKey;
    }
};

int main() {
    DiffieHellman dh1;
    DiffieHellman dh2;

    // Check that the DiffieHellman implementation works and two parties will agree on the same key
  
    if (dh1.getSharedSecretKey(dh2.getPublicKey()) == dh2.getSharedSecretKey(dh1.getPublicKey())) {
        std::cout << "Shared secret key: " << std::hex << std::setw(16) << std::setfill('0') << dh1.getSharedSecretKey(dh2.getPublicKey()) << std::endl;
    }

    return 0;
}
