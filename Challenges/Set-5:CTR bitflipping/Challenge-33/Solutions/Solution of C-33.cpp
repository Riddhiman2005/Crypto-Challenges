
#include <iostream>
#include <string>
#include <vector>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/sha.h>

std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), digest.data());
    return digest;
}

std::vector<unsigned char> performDiffieHellman(const BIGNUM* p, const BIGNUM* g) {
    DH* dh = DH_new();
    DH_set0_pqg(dh, p, nullptr, g);

    if (DH_generate_key(dh) != 1) {
        std::cout << "Failed to generate Diffie-Hellman keys." << std::endl;
        DH_free(dh);
        exit(1);
    }

    const BIGNUM* pub_key = nullptr;
    DH_get0_key(dh, &pub_key, nullptr);

    BIGNUM* shared_secret = BN_new();
    if (DH_compute_key(shared_secret, pub_key, dh) == -1) {
        std::cout << "Failed to compute shared secret." << std::endl;
        BN_free(shared_secret);
        DH_free(dh);
        exit(1);
    }

    std::vector<unsigned char> secret_bytes(BN_num_bytes(shared_secret));
    BN_bn2bin(shared_secret, secret_bytes.data());

    BN_free(shared_secret);
    DH_free(dh);

    return sha256(secret_bytes);
}

int main() {
    const char* p_hex =
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
        "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
        "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
        "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
        "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
        "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
        "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
        "fffffffffffff";

    const char* g_dec = "2";

    BIGNUM* p = nullptr;
    BIGNUM* g = nullptr;
    BIGNUM* bn = nullptr;

    BN_hex2bn(&p, p_hex);
    BN_dec2bn(&g, g_dec);

    std::vector<unsigned char> shared_key = performDiffieHellman(p, g);

    std::cout << "Shared Key: ";
    for (const auto& byte : shared_key) {
        printf("%02x", byte);
    }
    std::cout << std::endl;

    BN_free(p);
    BN_free(g);
    
    return 0;
}
