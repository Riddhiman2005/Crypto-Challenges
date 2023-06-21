#include <iostream>
#include <string>
#include <vector>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/bn.h>

class EchoBot {
public:
    EchoBot(BIGNUM* p, BIGNUM* g, BIGNUM* A) : p(p), g(g), A(A) {}

    BIGNUM* PubKey() {
        return A;
    }

    std::vector<unsigned char> Echo(const std::vector<unsigned char>& ciphertext) {
        return ciphertext;
    }

private:
    BIGNUM* p;
    BIGNUM* g;
    BIGNUM* A;
};

void withoutMitm() {
    BIGNUM* p = BN_new();
    BN_hex2bn(&p, "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff");
    BIGNUM* g = BN_new();
    BN_set_word(g, 5);

    BIGNUM* a = BN_new();
    BIGNUM* A = BN_new();
    BIGNUM* B = BN_new();
    BIGNUM* s = BN_new();
    BIGNUM* key = BN_new();

    BN_rand(a, BN_num_bits(p), 0, 0);
    BN_mod(a, a, p, NULL);
    BN_mod_exp(A, g, a, p, NULL);

    EchoBot bot(p, g, A);
    BN_copy(B, bot.PubKey());

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

    std::vector<unsigned char> responseCiphertext = bot.Echo(bytes);

    std::vector<unsigned char> decryptedResponse(responseCiphertext.size());
    std::vector<unsigned char> iv2(responseCiphertext.begin(), responseCiphertext.begin() + AES_BLOCK_SIZE);

    AES_set_decrypt_key(sha_digest_vec.data(), 128, &aes_key);
    AES_cbc_encrypt(responseCiphertext.data() + AES_BLOCK_SIZE, decryptedResponse.data(), responseCiphertext.size() - AES_BLOCK_SIZE, &aes_key, iv2.data(), AES_DECRYPT);
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

void withMitm(const std::string& msg, BIGNUM* p, BIGNUM* g, BIGNUM* g2, BIGNUM* expectedS) {
    BIGNUM* a = BN_new();
    BIGNUM* A = BN_new();
    BIGNUM* B = BN_new();
    BIGNUM* s = BN_new();
    BIGNUM* key = BN_new();

    BN_rand(a, BN_num_bits(p), 0, 0);
    BN_mod(a, a, p, NULL);
    BN_mod_exp(A, g, a, p, NULL);

    EchoBot bot(p, g2, g2);
    BN_copy(B, bot.PubKey());

    BN_mod_exp(s, B, a, p, NULL);

    unsigned char sha_digest[SHA_DIGEST_LENGTH];
    SHA1(BN_bn2bin(s), BN_num_bytes(s), sha_digest);
    std::vector<unsigned char> sha_digest_vec(sha_digest, sha_digest + SHA_DIGEST_LENGTH);

    BN_bin2bn(sha_digest_vec.data(), SHA_DIGEST_LENGTH, key);

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

    std::vector<unsigned char> responseCiphertext = bot.Echo(bytes);

    unsigned char sha_digest2[SHA_DIGEST_LENGTH];
    SHA1(BN_bn2bin(expectedS), BN_num_bytes(expectedS), sha_digest2);
    std::vector<unsigned char> sha_digest_vec2(sha_digest2, sha_digest2 + SHA_DIGEST_LENGTH);

    BN_bin2bn(sha_digest_vec2.data(), SHA_DIGEST_LENGTH, key);

    std::vector<unsigned char> decryptedMsg(responseCiphertext.size());
    std::vector<unsigned char> iv2(responseCiphertext.begin(), responseCiphertext.begin() + AES_BLOCK_SIZE);

    AES_set_decrypt_key(sha_digest_vec2.data(), 128, &aes_key);
    AES_cbc_encrypt(responseCiphertext.data() + AES_BLOCK_SIZE, decryptedMsg.data(), responseCiphertext.size() - AES_BLOCK_SIZE, &aes_key, iv2.data(), AES_DECRYPT);
    decryptedMsg.resize(decryptedMsg.size() - decryptedMsg.back());

    std::cout << std::string(decryptedMsg.begin(), decryptedMsg.end()) << std::endl;

    BN_free(a);
    BN_free(A);
    BN_free(B);
    BN_free(s);
    BN_free(key);
}

void Challenge35() {
    std::cout << std::endl;

    BIGNUM* p = BN_new();
    BN_hex2bn(&p, "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff");
    BIGNUM* g = BN_new();
    BN_set_word(g, 5);

    withoutMitm();

    withMitm("hello world 1", p, g, BN_new(), BN_new());
    withMitm("hello world 2", p, g, p, BN_new());

    BN_free(p);
    BN_free(g);
}

int main() {
    Challenge35();

    return 0;
}
