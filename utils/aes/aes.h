
#ifndef AES_H
#define AES_H

#include <cstdint>
#include <vector>

class AES {
public:
    AES(const std::vector<uint8_t>& key);
    ~AES();

    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& ciphertext);

private:
    std::vector<uint8_t> key_;
    std::vector<std::vector<uint8_t>> roundKeys_;

    void KeyExpansion();
    void AddRoundKey(std::vector<uint8_t>& state, int round);
    void SubBytes(std::vector<uint8_t>& state);
    void ShiftRows(std::vector<uint8_t>& state);
    void MixColumns(std::vector<uint8_t>& state);
    void InvSubBytes(std::vector<uint8_t>& state);
    void InvShiftRows(std::vector<uint8_t>& state);
    void InvMixColumns(std::vector<uint8_t>& state);

    uint8_t GFMul(uint8_t a, uint8_t b);
    uint8_t GFMulBy02(uint8_t value);
    uint8_t GFMulBy03(uint8_t value);
    uint8_t GFMulBy09(uint8_t value);
    uint8_t GFMulBy0B(uint8_t value);
    uint8_t GFMulBy0D(uint8_t value);
    uint8_t GFMulBy0E(uint8_t value);
};

#endif  // AES_H
