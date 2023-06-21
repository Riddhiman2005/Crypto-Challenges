
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <random>
#include <ctime>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

void PrintTitle(int set, int challenge) {
    std::cout << "Set " << set << " - Challenge " << challenge << std::endl << std::endl;
}

class passwordStore {
public:
    std::string I;
    std::vector<unsigned char> salt;
    BIGNUM* v;
    BIGNUM* b;
    BIGNUM* B;
    BIGNUM* u;

    passwordStore(const std::string& identity, const BIGNUM* N, const BIGNUM* g, const BIGNUM* k) : I(identity) {
        v = BN_new();
        b = BN_new();
        B = BN_new();
        u = BN_new();

        salt.resize(4);
        RAND_bytes(salt.data(), salt.size());

        std::vector<unsigned char> sha_digest(SHA256_DIGEST_LENGTH);
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, salt.data(), salt.size());
        SHA256_Update(&ctx, P.data(), P.size());
        SHA256_Final(sha_digest.data(), &ctx);

        BIGNUM* x = BN_new();
        BN_bin2bn(sha_digest.data(), sha_digest.size(), x);

        BN_mod_exp(v, g, x, N, NULL);

        BN_free(x);
    }

    ~passwordStore() {
        BN_free(v);
        BN_free(b);
        BN_free(B);
        BN_free(u);
    }
};

void Challenge36() {
    PrintTitle(5, 36);

    std::mt19937 gen(time(0));
    std::uniform_int_distribution<int> dist;

    BIGNUM* N = BN_new();
    BN_hex2bn(&N, "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff");

    BIGNUM* g = BN_new();
    BN_set_word(g, 2);

    BIGNUM* k = BN_new();
    BN_set_word(k, 3);

    // part 1: save password
    std::string I = "foo@bar.com";
    std::string P = "sup3r s3cr3t";
    passwordStore store(I, N, g, k);

    // part 2: start authentication
    BIGNUM* a = BN_new();
    BN_rand(a, BN_num_bits(N), 0, 0);
    BN_mod(a, a, N, NULL);

    BIGNUM* A = BN_new();
    BN_mod_exp(A, g, a, N, NULL);

    std::vector<unsigned char> salt = store.salt;
    BIGNUM* B = BN_new();
    BIGNUM* t = BN_new();
    BIGNUM* v = store.v;
    BIGNUM* b = BN_new();
    BN_rand(b, BN_num_bits(N), 0, 0);
    BN_mod(b, b, N, NULL);
    BN_mod_exp(B, g, b, N, NULL);
    BN_mul(t, k, v, NULL);
    BN_add(B, B, t);

    BN_CTX* ctx = BN_CTX_new();
    BN_mod(B, B, N, ctx);

    unsigned char uH[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, BN_bn2bin(A), BN_num_bytes(A));
    SHA256_Update(&sha_ctx, BN_bn2bin(B), BN_num_bytes(B));
    SHA256_Final(uH, &sha_ctx);
    BIGNUM* u = BN_new();
    BN_bin2bn(uH, sizeof(uH), u);

    unsigned char xH[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, salt.data(), salt.size());
    SHA256_Update(&sha_ctx, P.data(), P.size());
    SHA256_Final(xH, &sha_ctx);
    BIGNUM* x = BN_new();
    BN_bin2bn(xH, sizeof(xH), x);

    BIGNUM* S = BN_new();
    BIGNUM* t2 = BN_new();
    BN_exp(S, v, u, N, ctx);
    BN_mul(S, S, A, ctx);
    BN_mod_exp(S, S, b, N, ctx);

    unsigned char SH[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, BN_bn2bin(S), BN_num_bytes(S));
    SHA256_Final(SH, &sha_ctx);

    unsigned char K[SHA256_DIGEST_LENGTH];
    SHA256(SH, sizeof(SH), K);

    unsigned char expectedProof[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, K, sizeof(K));
    SHA256_Update(&sha_ctx, salt.data(), salt.size());
    SHA256_Final(expectedProof, &sha_ctx);

    bool res = std::memcmp(expectedProof, proof, SHA256_DIGEST_LENGTH) == 0;
    std::cout << std::boolalpha << res << std::endl;

    BN_free(N);
    BN_free(g);
    BN_free(k);
    BN_free(a);
    BN_free(A);
    BN_free(B);
    BN_free(t);
    BN_free(v);
    BN_free(b);
    BN_free(u);
    BN_free(x);
    BN_free(S);
    BN_CTX_free(ctx);
}

int main() {
    Challenge36();

    return 0;
}
