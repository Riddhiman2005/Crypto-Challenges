
#include <iostream>
#include <vector>
#include <stdexcept>
#include <openssl/bn.h>
#include "rsa.h"
#include "utils.h"

void Challenge40() {
    PrintTitle(5, 40);

    // Create 3 keys
    RSAKey pubKey1 = GenerateKeyPair(1024);
    RSAKey pubKey2 = GenerateKeyPair(1024);
    RSAKey pubKey3 = GenerateKeyPair(1024);

    // Encrypt a message 3 times
    std::string msg = "attack at dawn";
    BIGNUM* c1 = BN_new();
    BN_bin2bn(reinterpret_cast<const unsigned char*>(pubKey1.Encrypt(msg)), static_cast<int>(msg.length()), c1);

    BIGNUM* c2 = BN_new();
    BN_bin2bn(reinterpret_cast<const unsigned char*>(pubKey2.Encrypt(msg)), static_cast<int>(msg.length()), c2);

    BIGNUM* c3 = BN_new();
    BN_bin2bn(reinterpret_cast<const unsigned char*>(pubKey3.Encrypt(msg)), static_cast<int>(msg.length()), c3);

    // Crack the ciphertexts using CRT
    std::vector<BIGNUM*> ciphertexts = {c1, c2, c3};
    std::vector<BIGNUM*> moduli = {pubKey1.GetN(), pubKey2.GetN(), pubKey3.GetN()};

    BIGNUM* solution = nullptr;
    try {
        solution = CRT(ciphertexts, moduli);
    } catch (const std::runtime_error& e) {
        std::cerr << "CRT failed: " << e.what() << std::endl;
        return;
    }

    BIGNUM* plaintext = BN_new();
    BN_root(plaintext, solution, 3);

    std::cout << "plaintext: " << msg << std::endl;
    std::cout << "decrypted: " << BN_bn2hex(plaintext) << std::endl;

    BN_free(plaintext);
    BN_free(solution);
    BN_free(c1);
    BN_free(c2);
    BN_free(c3);

    std::cout << std::endl;
}

// Chinese Remainder Theorem (CRT) implementation
BIGNUM* CRT(const std::vector<BIGNUM*>& a, const std::vector<BIGNUM*>& n) {
    BIGNUM* p = BN_new();
    BN_copy(p, n[0]);
    for (size_t i = 1; i < n.size(); ++i) {
        BN_mul(p, p, n[i], nullptr);
    }

    BIGNUM* x = BN_new();
    BN_zero(x);
    BIGNUM* q = BN_new();
    BIGNUM* s = BN_new();
    BIGNUM* z = BN_new();
    for (size_t i = 0; i < a.size(); ++i) {
        BN_div(q, nullptr, p, n[i], nullptr);
        BN_gcd(z, s, n[i], q, nullptr);
        if (BN_cmp(z, BN_value_one()) != 0) {
            throw std::runtime_error("moduli are not coprime");
        }
        BN_mul(s, s, a[i], nullptr);
        BN_mul(s, s, q, nullptr);
        BN_add(x, x, s);
    }

    BN_mod(x, x, p, nullptr);

    BN_free(z);
    BN_free(s);
    BN_free(q);
    BN_free(p);

    return x;
}
