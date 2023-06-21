
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>
#include <openssl/sha.h>
#include <openssl/hmac.h>

typedef unsigned char byte;

class Utils {
public:
    static std::vector<byte> HmacSha256(const std::vector<byte>& key, const std::vector<byte>& message) {
        std::vector<byte> digest(SHA256_DIGEST_LENGTH);
        unsigned int length;
        HMAC(EVP_sha256(), key.data(), key.size(), message.data(), message.size(), digest.data(), &length);
        return digest;
    }
};

class PasswordStore {
public:
    std::string I;
    std::vector<byte> salt;
    std::vector<byte> v;
};

std::vector<byte> sha256(const std::vector<byte>& input) {
    std::vector<byte> digest(SHA256_DIGEST_LENGTH);
    SHA256(input.data(), input.size(), digest.data());
    return digest;
}

std::vector<byte> byteSliceToVector(const byte* data, size_t size) {
    return std::vector<byte>(data, data + size);
}

std::vector<byte> generateRandomBytes(size_t size) {
    std::vector<byte> randomBytes(size);
    std::random_device rd;
    std::default_random_engine rng(rd());
    std::uniform_int_distribution<byte> distribution(0, 255);
    for (size_t i = 0; i < size; ++i) {
        randomBytes[i] = distribution(rng);
    }
    return randomBytes;
}

PasswordStore savePassword(const std::string& I, const std::string& P) {
    PasswordStore store;
    store.I = I;
    store.salt = generateRandomBytes(16);
    std::vector<byte> input(store.salt.size() + P.size());
    std::copy(store.salt.begin(), store.salt.end(), input.begin());
    std::copy(P.begin(), P.end(), input.begin() + store.salt.size());
    store.v = sha256(input);
    return store;
}

std::vector<byte> authStep1(PasswordStore& store, const std::string& I) {
    if (store.I != I) {
        throw std::runtime_error("Invalid identity");
    }
    store.salt = generateRandomBytes(16);
    return store.salt;
}

bool authStep2(PasswordStore& store, const std::vector<byte>& A, const std::vector<byte>& proof) {
    std::vector<byte> K = sha256(std::vector<byte>(SHA256_DIGEST_LENGTH, 0));  // Zero-initialized vector
    std::vector<byte> expectedProof = Utils::HmacSha256(K, store.salt);
    return expectedProof == proof;
}

void challenge37() {
    std::srand(static_cast<unsigned>(std::time(0)));

    std::string N_str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
    std::vector<byte> N(N_str.size() / 2);
    for (size_t i = 0; i < N_str.size(); i += 2) {
        std::string byteStr = N_str.substr(i, 2);
        N[i / 2] = static_cast<byte>(std::stoi(byteStr, nullptr, 16));
    }

    std::string g_str = "02";
    std::vector<byte> g(g_str.size() / 2);
    for (size_t i = 0; i < g_str.size(); i += 2) {
        std::string byteStr = g_str.substr(i, 2);
        g[i / 2] = static_cast<byte>(std::stoi(byteStr, nullptr, 16));
    }

    std::string k_str = "03";
    std::vector<byte> k(k_str.size() / 2);
    for (size_t i = 0; i < k_str.size(); i += 2) {
        std::string byteStr = k_str.substr(i, 2);
        k[i / 2] = static_cast<byte>(std::stoi(byteStr, nullptr, 16));
    }

    std::string I = "foo@bar.com";
    std::string P = "sup3r s3cr3t";
    PasswordStore store = savePassword(I, P);

    std::vector<byte> salt = authStep1(store, I);

    std::vector<byte> S(SHA256_DIGEST_LENGTH, 0);  // Zero-initialized vector

    std::vector<byte> K = sha256(S);

    std::vector<byte> proof = Utils::HmacSha256(K, salt);

    for (int i = 0; i < 3; ++i) {
        std::vector<byte> A(SHA256_DIGEST_LENGTH, 0);  // Zero-initialized vector
        bool res = authStep2(store, A, proof);
        std::cout << i << "*N: " << std::boolalpha << res << std::endl;
    }
}

int main() {
    challenge37();
    return 0;
}
