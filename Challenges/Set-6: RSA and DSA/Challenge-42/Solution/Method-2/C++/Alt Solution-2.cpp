
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/bn.h>
#include <openssl/sha.h>

std::string byteToHex(unsigned char byte) {
    std::stringstream ss;
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    return ss.str();
}

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    for (unsigned char byte : bytes) {
        ss << byteToHex(byte);
    }
    return ss.str();
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

bool verify(const std::vector<unsigned char>& signature, const BIGNUM* modulus) {
    // Message should be of the form:
    // 0x00, 0x01, 0xff..., 0x00, 0x3021300906052b0e03021a05000414, hash...

    std::vector<unsigned char> data = signature;

    // Check first byte. 0x00 gets dropped because of BIGNUM.
    if (data[0] != 0x01) {
        return false;
    }

    // Eat all the 0xff
    int offset = 1;
    while (data[offset] == 0xff) {
        offset++;
        if (offset == data.size()) {
            return false;
        }
    }

    // ASN.1 GOOP comes from https://datatracker.ietf.org/doc/html/rfc3447#section-9.2
    std::vector<unsigned char> asn1Goop = {
        0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
    };
    for (unsigned char byte : asn1Goop) {
        if (data[offset] != byte) {
            return false;
        }
        offset++;
    }

    // Hash the message using SHA-1
    SHA_CTX shaContext;
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1_Init(&shaContext);
    SHA1_Update(&shaContext, &data[offset], data.size() - offset);
    SHA1_Final(hash, &shaContext);

    std::vector<unsigned char> computedHash(hash, hash + SHA_DIGEST_LENGTH);

    // Compare the computed hash with the remaining data
    if (computedHash != std::vector<unsigned char>(data.begin() + offset, data.end())) {
        return false;
    }

    return true;
}

std::vector<unsigned char> forge(const BIGNUM* modulus) {
    std::vector<unsigned char> forgedBlock = {
        0x01, 0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        0x92, 0x5a, 0x89, 0xb4, 0x3f, 0x3c, 0xaf, 0xf5, 0x07, 0xdb, 0x0a, 0x86, 0xd2, 0x0a, 0x24, 0x28, 0x00, 0x7f, 0x10, 0xb6
    };
    int goal = forgedBlock.size();

    for (int i = 0; i < 200; i++) {
        // Keep adding garbage until cube root returns the original data
        forgedBlock.push_back(0x01);
        std::vector<unsigned char> nBytes(forgedBlock.begin(), forgedBlock.end());
        BIGNUM* n = BN_bin2bn(nBytes.data(), nBytes.size(), nullptr);
        BIGNUM* r = BN_new();
        BIGNUM* t = BN_new();

        // Compute the cube root of n
        BN_exp(r, n, BN_new_word(1), modulus);
        BN_mod(t, r, modulus, nullptr);

        std::vector<unsigned char> tBytes(BN_num_bytes(t));
        BN_bn2bin(t, tBytes.data());

        if (std::equal(tBytes.begin(), tBytes.begin() + goal, forgedBlock.begin())) {
            BN_free(n);
            BN_free(r);
            BN_free(t);
            return tBytes;
        }

        BN_free(n);
        BN_free(r);
        BN_free(t);
    }

    throw std::runtime_error("Failed to forge the signature");
}

int main() {
    // Load the key and signature
    std::vector<unsigned char> signature = hexToBytes("420d9e40b0c881520ec8aa5e20338b14e46d2daca185863f6bb27ec3f83aa0d7e3b9352ee6972483911be4592bd403f5b671f84a9ff84e879a45ba56afec8bfe1164cdbf411160c1d34bc31cdf4cdd9700f2e11ca469ab2fa20207170989611af9ec066a68d974986e3a51452ade9a94a9b598f6c84b6d42777cf112a9fb73b8");

    BIGNUM* modulus = BN_new();
    BN_hex2bn(&modulus, "00d3a75c230ccb7b69f8f10d478588309d96bdef1b7042db4a587a4fd1dca880726d5674adb5ace47782ff0e8fdf73be141997a0f69ac598d873179e3e70d728831e4f7a4af9de4635422abc2943b14dafc5fd037e65c573937989c2d763ca08982d0fabf103f0c59045d3dc1d5cb3e994096fe7cb1607f9e3efbe71c71afbfe69");

    // Verify the original signature
    std::cout << "Original signature: " << (verify(signature, modulus) ? "valid" : "invalid") << std::endl;

    // Force a different signature
    std::vector<unsigned char> forgedSignature = forge(modulus);

    // Verify the forged signature
    std::cout << "Forged signature: " << (verify(forgedSignature, modulus) ? "valid" : "invalid") << std::endl;

    // Verify that the two signatures are different
    if (signature == forgedSignature) {
        throw std::runtime_error("Signatures don't differ");
    }

    BN_free(modulus);

    return 0;
}
