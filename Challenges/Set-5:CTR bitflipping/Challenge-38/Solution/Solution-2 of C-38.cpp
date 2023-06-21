
#include <iostream>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#define SHA256_DIGEST_LENGTH 32

// Calculate the SHA256 hash of the input data

std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);

    std::string result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        result += static_cast<char>(hash[i]);
    }

    return result;
}

// Generate a random 128-bit number
std::string generateRandomNumber() {
    unsigned char buffer[16];
    RAND_bytes(buffer, sizeof(buffer));

    std::string result;
    for (int i = 0; i < 16; i++) {
        result += static_cast<char>(buffer[i]);
    }

    return result;
}

// Perform the MITM attack
void performMitmAttack(const std::string& I, const std::string& P, const std::string& salt, const std::string& B, const std::string& u, const std::string& proof) {
    std::vector<std::string> dictionary = {"ba53ba11", "sup3r s3cr3t", "pa5ta lov3r"};

    for (const std::string& password : dictionary) {
        std::string x = sha256(salt + password);
        BIGNUM* S = BN_new();
        BIGNUM* b = BN_new();
        BIGNUM* uBN = BN_new();
        BIGNUM* A = BN_new();

        BN_hex2bn(&b, "42"); // Arbitrary value for b
        BN_hex2bn(&uBN, u.c_str());
        BN_hex2bn(&A, "2"); // Value of A received from the client

        // Calculate S = B^(a + ux) % N
        BIGNUM* t = BN_new();
        BIGNUM* t2 = BN_new();
        BN_mul(t, uBN, BN_bin2bn(reinterpret_cast<const unsigned char*>(x.c_str()), x.length(), nullptr), nullptr);
        BN_add(t, b, t);
        BN_mod_exp(S, BN_bin2bn(reinterpret_cast<const unsigned char*>(B.c_str()), B.length(), nullptr), t, nullptr, nullptr);

        // Calculate K = SHA256(S)
        std::string K = sha256(BN_bn2hex(S));

        // Calculate HMAC-SHA256(K, salt)
        std::string hmac = sha256(HMAC(EVP_sha256(), K.c_str(), K.length(), reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(), nullptr, nullptr));

        if (hmac == proof.substr(0, hmac.length())) {
            std::cout << "Cracked password: " << password << std::endl;
            break;
        }

        BN_free(S);
        BN_free(b);
        BN_free(uBN);
        BN_free(A);
        BN_free(t);
        BN_free(t2);
    }
}

int main() {
    std::string I = "foo@bar.com";
    std::string P = "sup3r s3cr3t";
    std::string salt;
    std::string B;
    std::string u;
    std::string proof;

    // Simulate server's step 1: Generate salt, B, and u
  
    salt = generateRandomNumber();
    B = "2"; // Set B as 2 (can be modified by MITM)
    u = generateRandomNumber();

    // Simulate client's step 2: Calculate the client's private and public keys
  
    BIGNUM* a = BN_new();
    BN_rand(a, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BIGNUM* A = BN_new();
    BIGNUM* N = BN_new();
    BN_hex2bn(&N, "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff");
    BN_mod_exp(A, BN_bin2bn(reinterpret_cast<const unsigned char*>(B.c_str()), B.length(), nullptr), a, N, nullptr);

    // Simulate server's step 2: Calculate the server's private key and HMAC
  
    std::string x = sha256(salt + P);
    BIGNUM* xBN = BN_new();
    BN_bin2bn(reinterpret_cast<const unsigned char*>(x.c_str()), x.length(), xBN);
    BIGNUM* v = BN_new();
    BIGNUM* b = BN_new();
    BIGNUM* S = BN_new();
    BIGNUM* K = BN_new();

    BN_rand(b, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_mod_exp(v, BN_bin2bn(reinterpret_cast<const unsigned char*>(I.c_str()), I.length(), nullptr), xBN, N, nullptr);
    BN_mod_exp(S, BN_bin2bn(reinterpret_cast<const unsigned char*>(A->d), A->top * sizeof(BN_ULONG), nullptr), b, N, nullptr);
    std::string K_str = sha256(BN_bn2hex(S));
    BN_bin2bn(reinterpret_cast<const unsigned char*>(K_str.c_str()), K_str.length(), K);

    proof = sha256(HMAC(EVP_sha256(), BN_bn2hex(K), strlen(BN_bn2hex(K)), reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(), nullptr, nullptr));

    // Simulate client's step 3: Validate the server's HMAC
    if (proof == sha256(HMAC(EVP_sha256(), BN_bn2hex(K), strlen(BN_bn2hex(K)), reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(), nullptr, nullptr))) {
        std::cout << "Authentication successful!" << std::endl;
    } else {
        std::cout << "Authentication failed!" << std::endl;
    }

    // Perform the MITM attack
    performMitmAttack(I, P, salt, B, u, proof);

    BN_free(a);
    BN_free(A);
    BN_free(N);
    BN_free(xBN);
    BN_free(v);
    BN_free(b);
    BN_free(S);
    BN_free(K);

    return 0;
}
