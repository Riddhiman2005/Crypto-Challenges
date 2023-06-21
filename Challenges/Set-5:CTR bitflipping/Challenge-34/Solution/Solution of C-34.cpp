
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

class EchoBot {
private:
    BIGNUM *p;
    BIGNUM *g;
    BIGNUM *b;
    BIGNUM *A;
    BIGNUM *B;

public:
    EchoBot(const BIGNUM *p, const BIGNUM *g, const BIGNUM *A) {
        this->p = BN_dup(p);
        this->g = BN_dup(g);
        this->b = BN_new();
        this->A = BN_dup(A);
        this->B = BN_new();
    }

    ~EchoBot() {
        BN_free(p);
        BN_free(g);
        BN_free(b);
        BN_free(A);
        BN_free(B);
    }

    BIGNUM* getPublicKey() {
        return B;
    }

    std::vector<unsigned char> echo(const std::vector<unsigned char>& ciphertext) {
        BIGNUM *s = BN_new();
        BIGNUM *key = BN_new();
        std::vector<unsigned char> plaintext;
        std::vector<unsigned char> responseCiphertext;

        // Establish key
        BN_mod_exp(s, A, b, p, NULL);
        SHA_CTX sha_ctx;
        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx, BN_bn2bin(s), BN_num_bytes(s));
        SHA1_Final(plaintext.data(), &sha_ctx);
        plaintext.resize(16);  // Ensure correct size for AES

        AES_KEY aes_key;
        AES_set_encrypt_key(plaintext.data(), 128, &aes_key);

        // Decrypt message
        std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + 16);
        std::vector<unsigned char> encryptedMsg(ciphertext.begin() + 16, ciphertext.end());
        std::vector<unsigned char> decryptedMsg(encryptedMsg.size());

        AES_cbc_encrypt(encryptedMsg.data(), decryptedMsg.data(), encryptedMsg.size(), &aes_key, iv.data(), AES_DECRYPT);
        decryptedMsg.resize(decryptedMsg.size() - decryptedMsg.back());  // Remove padding

        // Encrypt response
        std::vector<unsigned char> newPlaintext;
        newPlaintext.insert(newPlaintext.end(), "re: ", "re: " + 4);
        newPlaintext.insert(newPlaintext.end(), decryptedMsg.begin(), decryptedMsg.end());
        std::vector<unsigned char> responseIv(16);
        std::vector<unsigned char> responseCiphertext2(newPlaintext.size());
        RAND_bytes(responseIv.data(), responseIv.size());

        AES_set_encrypt_key(plaintext.data(), 128, &aes_key);
        AES_cbc_encrypt(newPlaintext.data(), responseCiphertext2.data(), newPlaintext.size(), &aes_key, responseIv.data(), AES_ENCRYPT);

        // Construct response
        responseCiphertext.insert(responseCiphertext.end(), responseIv.begin(), responseIv.end());
        responseCiphertext.insert(responseCiphertext.end(), responseCiphertext2.begin(), responseCiphertext2.end());

        BN_free(s);
        BN_free(key);

        return responseCiphertext;
    }
};

void withoutMitm() {
    BIGNUM *p = BN_new();
    BN_hex2bn(&p, "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff");
    BIGNUM *g = BN_new();
    BN_set_word(g, 5);

    BIGNUM *a = BN_new();
    BIGNUM *A = BN_new();
    BIGNUM *B = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *key = BN_new();

    BN_rand(a, BN_num_bits(p), 0, 0);
    BN_mod(a, a, p, NULL);
    BN_mod_exp(A, g, a, p, NULL);

    EchoBot bot(p, g, A);

    BN_mod_exp(s, bot.getPublicKey(), a, p, NULL);

    unsigned char sha_digest[SHA_DIGEST_LENGTH];
    SHA1(BN_bn2bin(s), BN_num_bytes(s), sha_digest);
    std::vector<unsigned char> sha_digest_vec(sha_digest, sha_digest + SHA_DIGEST_LENGTH);

    BN_bin2bn(sha_digest_vec.data(), SHA_DIGEST_LENGTH, key);

    std::string msg = "hello world";
    std::vector<unsigned char> iv(16);
    std::vector<unsigned char> ciphertext(msg.size() + AES_BLOCK_SIZE);

    RAND_bytes(iv.data(), iv.size());

    AES_KEY aes_key;
    AES_set_encrypt_key(sha_digest_vec.data(), 128, &aes_key);

    std::vector<unsigned char> paddedMsg(msg.begin(), msg.end());
    paddedMsg.resize((paddedMsg.size() / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE);

    AES_cbc_encrypt(paddedMsg.data(), ciphertext.data(), paddedMsg.size(), &aes_key, iv.data(), AES_ENCRYPT);

    std::vector<unsigned char> bytes;
    bytes.insert(bytes.end(), iv.begin(), iv.end());
    bytes.insert(bytes.end(), ciphertext.begin(), ciphertext.end());

    std::vector<unsigned char> responseCiphertext = bot.echo(bytes);

    std::vector<unsigned char> responseIv(responseCiphertext.begin(), responseCiphertext.begin() + 16);
    std::vector<unsigned char> encryptedResponse(responseCiphertext.begin() + 16, responseCiphertext.end());
    std::vector<unsigned char> decryptedResponse(encryptedResponse.size());

    AES_set_decrypt_key(sha_digest_vec.data(), 128, &aes_key);
    AES_cbc_encrypt(encryptedResponse.data(), decryptedResponse.data(), encryptedResponse.size(), &aes_key, responseIv.data(), AES_DECRYPT);
    decryptedResponse.resize(decryptedResponse.size() - decryptedResponse.back());

    std::cout << std::string(decryptedResponse.begin(), decryptedResponse.end()) << std::endl;

    BN_free(p);
    BN_free(g);
    BN_free(a);
    BN_free(A);
    BN_free(B);
    BN_free(s);
    BN_free(key);
}

void withMitm() {
    BIGNUM *p = BN_new();
    BN_hex2bn(&p, "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff");
    BIGNUM *g = BN_new();
    BN_set_word(g, 5);

    BIGNUM *a = BN_new();
    BIGNUM *A = BN_new();
    BIGNUM *B = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *key = BN_new();

    BN_rand(a, BN_num_bits(p), 0, 0);
    BN_mod(a, a, p, NULL);
    BN_mod_exp(A, g, a, p, NULL);

    EchoBot bot(p, g, p);
    BN_copy(B, p);

    BN_mod_exp(s, B, a, p, NULL);

    unsigned char sha_digest[SHA_DIGEST_LENGTH];
    SHA1(BN_bn2bin(s), BN_num_bytes(s), sha_digest);
    std::vector<unsigned char> sha_digest_vec(sha_digest, sha_digest + SHA_DIGEST_LENGTH);

    BN_bin2bn(sha_digest_vec.data(), SHA_DIGEST_LENGTH, key);

    std::string msg = "hello world";
    std::vector<unsigned char> iv(16);
    std::vector<unsigned char> ciphertext(msg.size() + AES_BLOCK_SIZE);

    RAND_bytes(iv.data(), iv.size());

    AES_KEY aes_key;
    AES_set_encrypt_key(sha_digest_vec.data(), 128, &aes_key);

    std::vector<unsigned char> paddedMsg(msg.begin(), msg.end());
    paddedMsg.resize((paddedMsg.size() / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE);

    AES_cbc_encrypt(paddedMsg.data(), ciphertext.data(), paddedMsg.size(), &aes_key, iv.data(), AES_ENCRYPT);

    std::vector<unsigned char> bytes;
    bytes.insert(bytes.end(), iv.begin(), iv.end());
    bytes.insert(bytes.end(), ciphertext.begin(), ciphertext.end());

    std::vector<unsigned char> responseCiphertext = bot.echo(bytes);

    std::vector<unsigned char> responseIv(responseCiphertext.begin(), responseCiphertext.begin() + 16);
    std::vector<unsigned char> encryptedResponse(responseCiphertext.begin() + 16, responseCiphertext.end());
    std::vector<unsigned char> decryptedResponse(encryptedResponse.size());

    AES_set_decrypt_key(sha_digest_vec.data(), 128, &aes_key);
    AES_cbc_encrypt(encryptedResponse.data(), decryptedResponse.data(), encryptedResponse.size(), &aes_key, responseIv.data(), AES_DECRYPT);
    decryptedResponse.resize(decryptedResponse.size() - decryptedResponse.back());

    std::vector<unsigned char> plaintext(bytes.begin() + 16, bytes.end());
    std::vector<unsigned char> decryptedMsg(plaintext.size());

    SHA1(BN_bn2bin(BN_new()), BN_num_bytes(BN_new()), sha_digest);
    std::vector<unsigned char> sha_digest_vec2(sha_digest, sha_digest + SHA_DIGEST_LENGTH);

    AES_set_decrypt_key(sha_digest_vec2.data(), 128, &aes_key);
    AES_cbc_encrypt(plaintext.data(), decryptedMsg.data(), plaintext.size(), &aes_key, iv.data(), AES_DECRYPT);
    decryptedMsg.resize(decryptedMsg.size() - decryptedMsg.back());

    std::cout << std::string(decryptedResponse.begin(), decryptedResponse.end()) << std::endl;

    BN_free(p);
    BN_free(g);
    BN_free(a);
    BN_free(A);
    BN_free(B);
    BN_free(s);
    BN_free(key);
}

int main() {
    withoutMitm();
    withMitm();
    return 0;
}

